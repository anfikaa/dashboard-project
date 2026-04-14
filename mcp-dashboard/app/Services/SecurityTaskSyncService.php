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

        $taskIds = SecurityTask::query()
            ->whereNotNull('summary')
            ->whereIn('status', [
                SecurityTaskStatus::Pending->value,
                SecurityTaskStatus::Running->value,
            ])
            ->latest()
            ->limit($limit)
            ->pluck('id');

        foreach ($taskIds as $taskId) {
            $task = SecurityTask::query()->find($taskId);

            if ($task) {
                $this->syncTask($task);
            }
        }

        return $taskIds->count();
    }

    public function syncRecentCompletedTasksMissingResults(int $limit = 10): int
    {
        $taskIds = SecurityTask::query()
            ->where('status', SecurityTaskStatus::Completed->value)
            ->whereNotNull('summary')
            ->latest('completed_at')
            ->latest('updated_at')
            ->limit($limit)
            ->pluck('id');

        $count = 0;

        foreach ($taskIds as $taskId) {
            $task = SecurityTask::query()->find($taskId);

            if (! $task) {
                continue;
            }

            $dispatches = collect(data_get($task->summary, 'dispatches', []));
            $needsImport = $dispatches->contains(function ($dispatch): bool {
                if (! is_array($dispatch)) {
                    return false;
                }

                return filled($dispatch['result_prefix'] ?? null)
                    && blank($dispatch['imported_at'] ?? null);
            });

            if (! $needsImport) {
                continue;
            }

            $this->syncTask($task);
            $count++;
        }

        return $count;
    }

    public function syncTask(SecurityTask $task): void
    {
        $task = SecurityTask::query()
            ->with('clusterAgent')
            ->findOrFail($task->getKey());

        $this->logInfo('Starting remote task sync.', [
            'task_id' => $task->task_id,
            'security_task_id' => $task->id,
        ]);

        $dispatches = collect(data_get($task->summary, 'dispatches', []))
            ->map(fn (array $dispatch): array => $this->sanitizeDispatchForStorage($dispatch))
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
                    'remote_status' => $dispatch['remote_status'] ?? 'PENDING',
                    'sync_error' => $exception->getMessage(),
                ];
            }
        }

        $failures = collect(data_get($task->summary, 'dispatch_failures', []))
            ->filter(fn ($entry): bool => is_string($entry) && filled($entry))
            ->values()
            ->all();

        $task->refresh();
        $this->updateTaskState($task, collect($syncedDispatches), $failures);
        $task->refresh();
    }

    protected function syncDispatch(SecurityTask $task, ?ClusterAgent $clusterAgent, array $dispatch): array
    {
        $remoteTaskId = (string) ($dispatch['remote_task_id'] ?? '');
        $clusterSortKey = (string) ($dispatch['cluster_sort_key'] ?? '');
        $clusterName = (string) ($dispatch['cluster_name'] ?? ($clusterAgent?->cluster_name ?? ''));
        $tool = (string) ($dispatch['tool'] ?? '');
        $this->logInfo('Fetching remote task items from DynamoDB.', [
            'task_id' => $task->task_id,
            'remote_task_id' => $remoteTaskId,
            'cluster_sort_key' => $clusterSortKey,
        ]);

        $records = $this->getRemoteTaskItems($remoteTaskId);
        $meta = $records->firstWhere('SK', 'META') ?? $records->firstWhere('sk', 'META') ?? [];
        $clusterRecord = $this->resolveClusterRecord(
            records: $records,
            clusterSortKey: $clusterSortKey,
            clusterName: $clusterName,
            tool: $tool,
        );

        $clusterStatusRaw = $clusterRecord['status'] ?? $clusterRecord['STATUS'] ?? $clusterRecord['Status'] ?? 'PENDING';
        $metaStatusRaw    = $meta['status'] ?? $meta['STATUS'] ?? $meta['Status'] ?? 'PENDING';
        
        $remoteStatus = Str::upper((string) $clusterStatusRaw);
        $metaStatus   = Str::upper((string) $metaStatusRaw);

        if (in_array($metaStatus, ['COMPLETED', 'FAILED'], true)) {
            $remoteStatus = $metaStatus;
        }
        $updatedAt = (string) ($clusterRecord['updated_at'] ?? $meta['updated_at'] ?? '');
        $createdAt = (string) ($clusterRecord['created_at'] ?? $meta['created_at'] ?? '');
        $resultPrefix = rtrim((string) ($dispatch['result_prefix'] ?? ''), '/');

        $files = $resultPrefix !== '' && filled($tool)
            ? $this->scanService->getS3ResultFilesForTool($resultPrefix, $tool)
            : collect();

        // Fallback: If agent failed to update DynamoDB to COMPLETED but S3 files exist, override to COMPLETED
        if (! in_array($remoteStatus, ['COMPLETED', 'FAILED'], true) && $files->isNotEmpty()) {
            $this->logInfo('S3 files found but remote status is still RUNNING — overriding to COMPLETED.', [
                'remote_task_id' => $remoteTaskId,
                'file_count' => $files->count(),
            ]);
            $remoteStatus = 'COMPLETED';
        }

        // Zombie Fallback: If task is stuck in RUNNING/PENDING for > 60 minutes, mark as FAILED
        if (in_array($remoteStatus, ['PENDING', 'RUNNING'], true)) {
            $refTime = $updatedAt ?: $createdAt;
            if (filled($refTime)) {
                try {
                    $minutesStuck = Carbon::parse($refTime)->diffInMinutes(now());
                    if ($minutesStuck > 60) {
                        $this->logWarning('Remote task appears to be a zombie (stuck > 60 min). Forcing FAILED status.', [
                            'remote_task_id' => $remoteTaskId,
                            'minutes_stuck' => $minutesStuck,
                            'last_updated_at' => $refTime,
                        ]);
                        $remoteStatus = 'FAILED';
                    }
                } catch (\Throwable) {
                    // ignore parse errors
                }
            }
        }

        $synced = array_merge($dispatch, [
            'remote_status' => $remoteStatus,
            'dynamodb_meta_status' => $metaStatus,
            'dynamodb_cluster_status' => Str::upper((string) $clusterStatusRaw),
            'dynamodb_cluster_sk' => (string) ($clusterRecord['SK'] ?? $clusterRecord['sk'] ?? ''),
            'remote_created_at' => $createdAt,
            'remote_updated_at' => $updatedAt,
            'result_prefix' => $resultPrefix,
        ]);

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

        $files = $resultPrefix !== '' && filled($tool)
            ? $this->scanService->getS3ResultFilesForTool($resultPrefix, $tool)
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
                'imported_at' => now()->utc()->toIso8601String(),
                'findings_count' => 0,
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
        $terminalDispatches = $dispatches
            ->filter(fn (array $dispatch): bool => in_array($this->resolveTerminalStatus($dispatch), ['COMPLETED', 'FAILED'], true));
        $terminalCount = $terminalDispatches->count();

        $dispatchProcessingErrors = $dispatches
            ->map(fn (array $dispatch): ?string => $dispatch['import_error'] ?? $dispatch['sync_error'] ?? null)
            ->filter(fn (?string $error): bool => filled($error))
            ->values()
            ->all();

        $importedCount = $dispatches
            ->filter(function (array $dispatch): bool {
                $status = $this->resolveTerminalStatus($dispatch);

                return in_array($status, ['COMPLETED', 'FAILED'], true)
                    && (
                        filled($dispatch['imported_at'] ?? null)
                        || filled($dispatch['import_error'] ?? null)
                        || filled($dispatch['sync_error'] ?? null)
                    );
            })
            ->count();

        $runningCount = $dispatches
            ->filter(fn (array $dispatch): bool => ! in_array($this->resolveTerminalStatus($dispatch), ['COMPLETED', 'FAILED'], true))
            ->count();

        $completedCount = $dispatches
            ->filter(fn (array $dispatch): bool => $this->resolveTerminalStatus($dispatch) === 'COMPLETED')
            ->count();

        $failedCount = $dispatches
            ->filter(fn (array $dispatch): bool => $this->resolveTerminalStatus($dispatch) === 'FAILED')
            ->count() + count($dispatchFailures) + count($dispatchProcessingErrors);

        $progress = min(100, max(20, (int) round(($terminalCount / $total) * 100)));

        [$status, $message] = match (true) {
            $runningCount > 0 || $terminalCount < $total => [
                SecurityTaskStatus::Running,
                sprintf(
                    'Waiting for %d of %d remote scan dispatch(es) to finish.',
                    $total - $terminalCount,
                    $total,
                ),
            ],
            ! empty($dispatchProcessingErrors) && $completedCount > 0 => [
                SecurityTaskStatus::Completed,
                sprintf(
                    'Remote scan finished for task [%s], but %d dispatch import(s) need manual review. Latest issue: %s',
                    $task->task_id,
                    count($dispatchProcessingErrors),
                    Str::limit($dispatchProcessingErrors[0], 180),
                ),
            ],
            ! empty($dispatchProcessingErrors) || ($terminalDispatches->isNotEmpty() && $completedCount === 0) => [
                SecurityTaskStatus::Failed,
                sprintf(
                    'Remote scan finished for task [%s], but result import failed. Latest issue: %s',
                    $task->task_id,
                    Str::limit($dispatchProcessingErrors[0] ?? 'No result files could be imported from the completed remote dispatch.', 180),
                ),
            ],
            $completedCount > 0 => [
                SecurityTaskStatus::Completed,
                sprintf(
                    'Remote scan completed in DynamoDB for task [%s]. Imported %d dispatch result set(s).',
                    $task->task_id,
                    $importedCount,
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
        $summary['dispatches'] = $dispatches
            ->map(fn (array $dispatch): array => $this->sanitizeDispatchForStorage($dispatch))
            ->values()
            ->all();
        $summary['dispatch_failures'] = $dispatchFailures;
        $summary['remote_totals'] = [
            'total' => $total,
            'completed' => $completedCount,
            'failed' => $failedCount,
            'ready' => $terminalCount,
            'imported' => $importedCount,
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

    protected function resolveTerminalStatus(array $dispatch): string
    {
        foreach (['dynamodb_meta_status', 'remote_status', 'dynamodb_cluster_status'] as $key) {
            $status = Str::upper((string) ($dispatch[$key] ?? ''));

            if ($status !== '') {
                if (in_array($status, ['PENDING', 'RUNNING'], true) && $this->hasInlineAgentResult($dispatch)) {
                    return 'COMPLETED';
                }

                return $status;
            }
        }

        if ($this->hasInlineAgentResult($dispatch)) {
            return 'COMPLETED';
        }

        return 'PENDING';
    }

    protected function hasInlineAgentResult(array $dispatch): bool
    {
        $response = $dispatch['agent_response'] ?? null;

        if (! is_array($response)) {
            return false;
        }

        return collect($response)->contains(function ($entry): bool {
            if (! is_array($entry)) {
                return false;
            }

            $result = $entry['result'] ?? null;

            if (! is_array($result)) {
                return false;
            }

            if (($result['success'] ?? null) === true) {
                return true;
            }

            if (($result['return_code'] ?? null) === 0) {
                return true;
            }

            if (filled($result['stdout'] ?? null)) {
                return true;
            }

            return false;
        });
    }

    protected function sanitizeDispatchForStorage(array $dispatch): array
    {
        if (! array_key_exists('agent_response', $dispatch) || ! is_array($dispatch['agent_response'])) {
            return $dispatch;
        }

        $dispatch['agent_response'] = collect($dispatch['agent_response'])
            ->map(function (mixed $entry): mixed {
                if (! is_array($entry)) {
                    return $entry;
                }

                $result = $entry['result'] ?? null;

                if (! is_array($result)) {
                    return $entry;
                }

                $stdout = $result['stdout'] ?? null;

                return array_merge($entry, [
                    'result' => array_merge($result, [
                        'stdout' => is_string($stdout) ? Str::limit($stdout, 2000) : $stdout,
                        'stdout_truncated' => is_string($stdout) && strlen($stdout) > 2000,
                        'stdout_size' => is_string($stdout) ? strlen($stdout) : null,
                    ]),
                ]);
            })
            ->values()
            ->all();

        return $dispatch;
    }

    protected function resolveClusterRecord(
        Collection $records,
        string $clusterSortKey,
        string $clusterName,
        string $tool,
    ): array {
        $candidates = $records
            ->filter(fn (array $record): bool => (($record['SK'] ?? $record['sk'] ?? null) !== 'META'))
            ->values();

        if ($candidates->isEmpty()) {
            return [];
        }

        $normalizedTool = $this->normalizeToolName($tool);

        $matched = $candidates
            ->filter(function (array $record) use ($clusterSortKey, $clusterName, $normalizedTool): bool {
                $recordSk = (string) ($record['SK'] ?? $record['sk'] ?? '');
                $recordCluster = (string) ($record['cluster_name'] ?? $record['cluster'] ?? '');
                $recordTool = $this->normalizeToolName((string) ($record['tool'] ?? ''));

                $matchesExactSk = $clusterSortKey !== '' && $recordSk === $clusterSortKey;
                $matchesCluster = $clusterName !== '' && (
                    $recordCluster === $clusterName
                    || Str::endsWith($recordSk, '#' . $clusterName)
                    || Str::contains($recordSk, $clusterName)
                );
                $matchesTool = $normalizedTool === '' || $recordTool === '' || $recordTool === $normalizedTool;

                return ($matchesExactSk || $matchesCluster) && $matchesTool;
            })
            ->values();

        $pool = $matched->isNotEmpty() ? $matched : $candidates;

        return $pool
            ->sortByDesc(function (array $record): array {
                $status = Str::upper((string) ($record['status'] ?? $record['STATUS'] ?? $record['Status'] ?? 'PENDING'));
                $updatedAt = (string) ($record['updated_at'] ?? '');

                return [
                    match ($status) {
                        'COMPLETED' => 3,
                        'FAILED' => 2,
                        'RUNNING' => 1,
                        default => 0,
                    },
                    $updatedAt,
                ];
            })
            ->first() ?? [];
    }

    protected function normalizeToolName(string $tool): string
    {
        return match (strtolower(str_replace('_', '-', trim($tool)))) {
            'rbac', 'rbac-tool', 'rbac-tool-' => 'rbac-tool',
            'kubebench', 'kube-bench' => 'kubebench',
            'kubescape', 'kube-escape' => 'kubescape',
            'checkov', 'check-ov' => 'checkov',
            'nmap', 'n-map' => 'nmap',
            default => strtolower(str_replace('_', '-', trim($tool))),
        };
    }

    protected function getRemoteTaskItems(string $remoteTaskId): Collection
    {
        $client = $this->makeDynamoDbClient();
        $marshaler = new Marshaler();

        $result = $client->query([
            'TableName' => $this->dynamoTableName(),
            'KeyConditionExpression' => 'PK = :pk',
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
