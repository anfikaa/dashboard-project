<?php

namespace App\Services;

use App\Enums\SecurityTaskStatus;
use App\Models\ClusterAgent;
use App\Models\SecurityTask;
use App\Models\SecurityTaskResult;
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class SecurityTaskSyncService
{
    public function __construct(
        protected ScanService $scanService,
    ) {}

    public function syncRecentTasks(int $limit = 20): int
    {
        $this->logInfo('Refreshing recent remote tasks.', [
            'limit' => $limit,
        ]);

        $tasks = SecurityTask::query()
            ->with('clusterAgent')
            ->whereNotNull('summary')
            ->latest()
            ->limit($limit)
            ->get();

        foreach ($tasks as $task) {
            $this->syncTask($task);
        }

        return $tasks->count();
    }

    public function syncTask(SecurityTask $task): void
    {
        $this->logInfo('Starting remote task sync.', [
            'task_id' => $task->task_id,
            'security_task_id' => $task->id,
        ]);

        $dispatches = collect(data_get($task->summary, 'dispatches', []))
            ->filter(fn (array $dispatch): bool => filled($dispatch['remote_task_id'] ?? null))
            ->values();

        if ($dispatches->isEmpty()) {
            $this->logDebug('Skipping remote task sync because no dispatch metadata was found.', [
                'task_id' => $task->task_id,
            ]);

            return;
        }

        $clusterAgent = $task->clusterAgent;
        $syncedDispatches = [];

        foreach ($dispatches as $dispatch) {
            try {
                $syncedDispatches[] = $this->syncDispatch($task, $clusterAgent, $dispatch);
            } catch (Throwable $exception) {
                report($exception);
                $this->logError('Dispatch sync failed.', [
                    'task_id' => $task->task_id,
                    'remote_task_id' => $dispatch['remote_task_id'] ?? null,
                ], $exception);

                $syncedDispatches[] = $dispatch + [
                    'sync_error' => $exception->getMessage(),
                ];
            }
        }

        $failures = collect(data_get($task->summary, 'dispatch_failures', []))
            ->filter(fn ($entry): bool => is_string($entry) && filled($entry))
            ->values()
            ->all();

        $this->updateTaskState($task, collect($syncedDispatches), $failures);
    }

    protected function syncDispatch(SecurityTask $task, ?ClusterAgent $clusterAgent, array $dispatch): array
    {
        $remoteTaskId = (string) ($dispatch['remote_task_id'] ?? '');
        $clusterSortKey = (string) ($dispatch['cluster_sort_key'] ?? '');
        $this->logInfo('Fetching remote task items from DynamoDB.', [
            'task_id' => $task->task_id,
            'remote_task_id' => $remoteTaskId,
            'cluster_sort_key' => $clusterSortKey,
        ]);

        $records = $this->getRemoteTaskItems($remoteTaskId);
        $meta = $records->firstWhere('sk', 'META') ?? [];
        $clusterRecord = $records->firstWhere('sk', $clusterSortKey)
            ?? $records->first(fn (array $record): bool => ($record['sk'] ?? null) !== 'META')
            ?? [];

        $remoteStatus = Str::upper((string) ($clusterRecord['status'] ?? $meta['status'] ?? 'PENDING'));
        $updatedAt = (string) ($clusterRecord['updated_at'] ?? $meta['updated_at'] ?? '');
        $createdAt = (string) ($clusterRecord['created_at'] ?? $meta['created_at'] ?? '');
        $resultPrefix = (string) ($dispatch['result_prefix'] ?? '');

        $synced = $dispatch + [
            'remote_status' => $remoteStatus,
            'remote_created_at' => $createdAt,
            'remote_updated_at' => $updatedAt,
            'result_prefix' => $resultPrefix,
        ];

        if (! in_array($remoteStatus, ['COMPLETED', 'FAILED'], true)) {
            $this->logInfo('Remote task is not ready for result import yet.', [
                'task_id' => $task->task_id,
                'remote_task_id' => $remoteTaskId,
                'remote_status' => $remoteStatus,
            ]);

            return $synced;
        }

        if (filled($dispatch['imported_at'] ?? null)) {
            return $synced;
        }

        try {
            $importResult = $this->importDispatchResults(
                task: $task,
                dispatch: $synced,
                remoteStatus: $remoteStatus,
                clusterAgent: $clusterAgent,
            );

            return $synced + $importResult;
        } catch (Throwable $exception) {
            report($exception);
            $this->logError('Failed to import remote dispatch results.', [
                'task_id' => $task->task_id,
                'remote_task_id' => $remoteTaskId,
                'remote_status' => $remoteStatus,
            ], $exception);

            return $synced + [
                'import_error' => $exception->getMessage(),
            ];
        }
    }

    protected function importDispatchResults(
        SecurityTask $task,
        array $dispatch,
        string $remoteStatus,
        ?ClusterAgent $clusterAgent,
    ): array {
        $tool = (string) ($dispatch['tool'] ?? '');
        $resultPrefix = (string) ($dispatch['result_prefix'] ?? '');
        $remoteTaskId = (string) ($dispatch['remote_task_id'] ?? '');
        $clusterName = (string) ($dispatch['cluster_name'] ?? ($clusterAgent?->cluster_name ?? 'Unknown cluster'));

        $files = $resultPrefix !== ''
            ? $this->scanService->getS3ResultFiles($resultPrefix)
            : collect();

        $this->logInfo('Inspecting S3 result files for remote dispatch.', [
            'task_id' => $task->task_id,
            'remote_task_id' => $remoteTaskId,
            'tool' => $tool,
            'result_prefix' => $resultPrefix,
            'file_count' => $files->count(),
        ]);

        SecurityTaskResult::query()
            ->where('security_task_id', $task->id)
            ->where('source_tool', $tool)
            ->delete();

        if ($files->isEmpty()) {
            if ($remoteStatus === 'FAILED') {
                $this->logWarning('No S3 files found for failed remote dispatch; creating synthetic failure finding.', [
                    'task_id' => $task->task_id,
                    'remote_task_id' => $remoteTaskId,
                    'tool' => $tool,
                ]);

                $this->createExecutionFailureResult($task, $tool, $clusterName, $remoteTaskId);

                return [
                    'imported_at' => now()->utc()->toIso8601String(),
                    'findings_count' => 1,
                    'result_files' => [],
                ];
            }

            return [
                'result_files' => [],
            ];
        }

        $findings = $files
            ->flatMap(fn (array $file): Collection => $this->scanService->parseFile($file))
            ->values();

        $this->logInfo('Parsed findings from remote dispatch result files.', [
            'task_id' => $task->task_id,
            'remote_task_id' => $remoteTaskId,
            'tool' => $tool,
            'findings_count' => $findings->count(),
        ]);

        if ($findings->isEmpty() && $remoteStatus === 'FAILED') {
            $this->createExecutionFailureResult($task, $tool, $clusterName, $remoteTaskId);

            return [
                'imported_at' => now()->utc()->toIso8601String(),
                'findings_count' => 1,
                'result_files' => $files->pluck('path')->values()->all(),
            ];
        }

        if ($findings->isEmpty()) {
            return [
                'imported_at' => now()->utc()->toIso8601String(),
                'findings_count' => 0,
                'result_files' => $files->pluck('path')->values()->all(),
            ];
        }

        foreach ($findings as $finding) {
            SecurityTaskResult::create([
                'security_task_id' => $task->id,
                'task_identifier' => $task->task_id,
                'source_tool' => $finding['tool'],
                'cluster_name' => $finding['cluster_name'] ?? $clusterName,
                'severity' => $finding['status_bucket'],
                'scan_finding' => $this->formatFinding($finding),
                'recommendation' => $finding['recommendation'] ?? 'Review the reported issue and apply the recommended hardening control.',
                'suggestion' => $this->makeSuggestion($finding),
                'metadata' => $finding['metadata'] ?? [],
                'scanned_at' => $finding['scanned_at'] ?? Carbon::now(),
            ]);
        }

        return [
            'imported_at' => now()->utc()->toIso8601String(),
            'findings_count' => $findings->count(),
            'result_files' => $files->pluck('path')->values()->all(),
        ];
    }

    protected function updateTaskState(SecurityTask $task, Collection $dispatches, array $dispatchFailures): void
    {
        $total = max(1, $dispatches->count());
        $readyCount = $dispatches
            ->filter(function (array $dispatch): bool {
                $status = Str::upper((string) ($dispatch['remote_status'] ?? 'PENDING'));

                return in_array($status, ['COMPLETED', 'FAILED'], true)
                    && filled($dispatch['imported_at'] ?? null);
            })
            ->count();

        $runningCount = $dispatches
            ->filter(fn (array $dispatch): bool => ! in_array(Str::upper((string) ($dispatch['remote_status'] ?? 'PENDING')), ['COMPLETED', 'FAILED'], true))
            ->count();

        $completedCount = $dispatches
            ->filter(fn (array $dispatch): bool => Str::upper((string) ($dispatch['remote_status'] ?? '')) === 'COMPLETED')
            ->count();

        $failedCount = $dispatches
            ->filter(fn (array $dispatch): bool => Str::upper((string) ($dispatch['remote_status'] ?? '')) === 'FAILED')
            ->count() + count($dispatchFailures);

        $progress = min(100, max(20, (int) round(($readyCount / $total) * 100)));

        [$status, $message] = match (true) {
            $runningCount > 0 || $readyCount < $total => [
                SecurityTaskStatus::Running,
                sprintf(
                    'Waiting for %d of %d remote scan dispatch(es) to finish writing results.',
                    $total - $readyCount,
                    $total,
                ),
            ],
            $completedCount > 0 => [
                SecurityTaskStatus::Completed,
                sprintf(
                    'Imported %d remote dispatch result set(s) for task [%s].',
                    $readyCount,
                    $task->task_id,
                ),
            ],
            default => [
                SecurityTaskStatus::Failed,
                sprintf(
                    'All %d remote dispatch(es) ended in failure for task [%s].',
                    $total,
                    $task->task_id,
                ),
            ],
        };

        $summary = $task->summary ?? [];
        $summary['dispatches'] = $dispatches->values()->all();
        $summary['dispatch_failures'] = $dispatchFailures;
        $summary['remote_totals'] = [
            'total' => $total,
            'completed' => $completedCount,
            'failed' => $failedCount,
            'ready' => $readyCount,
            'running' => $runningCount,
        ];

        $task->update([
            'status' => $status,
            'progress' => $status === SecurityTaskStatus::Completed || $status === SecurityTaskStatus::Failed ? 100 : $progress,
            'summary' => $summary,
            'last_message' => $message,
            'completed_at' => $status === SecurityTaskStatus::Running ? null : now(),
        ]);

        $this->logInfo('Updated local task state after remote sync.', [
            'task_id' => $task->task_id,
            'status' => $status->value,
            'progress' => $status === SecurityTaskStatus::Completed || $status === SecurityTaskStatus::Failed ? 100 : $progress,
            'remote_totals' => $summary['remote_totals'] ?? [],
        ]);
    }

    protected function getRemoteTaskItems(string $remoteTaskId): Collection
    {
        $client = $this->makeDynamoDbClient();
        $marshaler = new Marshaler();

        $result = $client->query([
            'TableName' => $this->dynamoTableName(),
            'KeyConditionExpression' => 'pk = :pk',
            'ExpressionAttributeValues' => [
                ':pk' => ['S' => $remoteTaskId],
            ],
        ]);

        $this->logInfo('DynamoDB remote task query finished.', [
            'table' => $this->dynamoTableName(),
            'remote_task_id' => $remoteTaskId,
            'item_count' => count($result['Items'] ?? []),
        ]);

        return collect($result['Items'] ?? [])
            ->map(fn (array $item): array => $marshaler->unmarshalItem($item))
            ->values();
    }

    protected function createExecutionFailureResult(SecurityTask $task, string $tool, string $clusterName, string $remoteTaskId): void
    {
        SecurityTaskResult::create([
            'security_task_id' => $task->id,
            'task_identifier' => $task->task_id,
            'source_tool' => $tool,
            'cluster_name' => $clusterName,
            'severity' => 'FAIL',
            'scan_finding' => sprintf('The remote %s execution failed before a result file was written.', $tool),
            'recommendation' => 'Review the agent execution logs and rerun the task after correcting the failure.',
            'suggestion' => 'Confirm the backend agent endpoint, credentials, and cluster connectivity for this tool.',
            'metadata' => [
                'tool' => $tool,
                'remote_task_id' => $remoteTaskId,
                'status_bucket' => 'FAIL',
                'object' => $clusterName,
            ],
            'scanned_at' => now(),
        ]);

        $this->logWarning('Stored synthetic failure finding for remote dispatch.', [
            'task_id' => $task->task_id,
            'remote_task_id' => $remoteTaskId,
            'tool' => $tool,
            'cluster_name' => $clusterName,
        ]);
    }

    protected function formatFinding(array $finding): string
    {
        $findingText = $finding['description'] ?? 'Finding generated from scan result.';
        $object = trim((string) ($finding['object'] ?? ''));
        $actual = trim((string) data_get($finding, 'metadata.actual', ''));

        if (filled($object)) {
            $findingText .= ' Affected object: ' . $object . '.';
        }

        if (filled($actual)) {
            $findingText .= ' Actual value: ' . $actual;
        }

        return $findingText;
    }

    protected function makeSuggestion(array $finding): string
    {
        return $finding['suggestion']
            ?? match ($finding['status_bucket'] ?? null) {
                'FAIL' => 'Treat this as a priority issue, remediate the control, then rerun the task to validate the fix.',
                'WARN' => 'Review the configuration with the platform owner and confirm whether the warning is acceptable or needs remediation.',
                default => 'No additional action is required.',
            };
    }

    protected function dynamoTableName(): string
    {
        return (string) env('SECURITY_TASKS_DYNAMODB_TABLE', 'intern-tasks');
    }

    protected function makeDynamoDbClient(): DynamoDbClient
    {
        $config = [
            'version' => 'latest',
            'region' => env('AWS_DYNAMODB_REGION', env('AWS_DEFAULT_REGION')),
        ];

        if (filled(env('AWS_DYNAMODB_ENDPOINT'))) {
            $config['endpoint'] = env('AWS_DYNAMODB_ENDPOINT');
        }

        return new DynamoDbClient($config);
    }

    protected function logInfo(string $message, array $context = []): void
    {
        Log::channel('security_tasks')->info($message, $context);
    }

    protected function logDebug(string $message, array $context = []): void
    {
        Log::channel('security_tasks')->debug($message, $context);
    }

    protected function logWarning(string $message, array $context = []): void
    {
        Log::channel('security_tasks')->warning($message, $context);
    }

    protected function logError(string $message, array $context = [], ?Throwable $exception = null): void
    {
        Log::channel('security_tasks')->error($message, $context + array_filter([
            'exception' => $exception?->getMessage(),
            'trace' => $exception?->getTraceAsString(),
        ]));
    }
}
