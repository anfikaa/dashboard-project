<?php

namespace App\Services;

use App\Enums\SecurityTaskStatus;
use App\Models\ClusterAgent;
use App\Models\SecurityTask;
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

class TaskExecutionService
{
    protected const TASK_META_SORT_KEY = 'META';

    public static function getAvailableTools(): array
    {
        return [
            'checkov' => 'Checkov',
            'kubebench' => 'Kube Bench',
            'kubescape' => 'Kubescape',
            'nmap' => 'Nmap',
            'rbac-tool' => 'RBAC Tool',
        ];
    }

    public function run(SecurityTask $task): void
    {
        $task->loadMissing('clusterAgent');

        $agent = $task->clusterAgent;
        $selectedTools = collect($task->tools ?? [])
            ->filter(fn (?string $tool): bool => array_key_exists((string) $tool, self::getAvailableTools()))
            ->values()
            ->all();

        if (! $agent instanceof ClusterAgent) {
            $this->logWarning('Task dispatch aborted because the cluster agent was not found.', [
                'task_id' => $task->task_id,
                'cluster_agent_id' => $task->cluster_agent_id,
            ]);

            $task->update([
                'status' => SecurityTaskStatus::Failed,
                'progress' => 0,
                'completed_at' => now(),
                'last_message' => 'The selected cluster agent could not be found.',
            ]);

            return;
        }

        $task->update([
            'status' => SecurityTaskStatus::Pending,
            'progress' => 5,
            'started_at' => now(),
            'completed_at' => null,
            'last_message' => 'Validating cluster agent health and preparing remote scan task dispatch.',
        ]);

        try {
            if ($selectedTools === []) {
                throw new RuntimeException('Choose at least one supported security tool before dispatching the task.');
            }

            $this->logInfo('Starting remote task dispatch.', [
                'task_id' => $task->task_id,
                'cluster_name' => $agent->cluster_name,
                'cluster_agent_id' => $agent->id,
                'selected_tools' => $selectedTools,
            ]);

            $baseUrl = $this->resolveAgentBaseUrl($agent);
            $health = $this->assertAgentHealth($baseUrl, $agent);
            $dispatched = [];
            $failures = [];
            $now = now()->utc()->toIso8601String();

            foreach ($selectedTools as $tool) {
                $remoteTaskId = (string) Str::uuid();
                $parameters = $this->buildParameters($tool);

                $this->logInfo('Preparing remote dispatch record.', [
                    'task_id' => $task->task_id,
                    'tool' => $tool,
                    'remote_task_id' => $remoteTaskId,
                    'cluster_name' => $agent->cluster_name,
                    'parameters' => $parameters,
                ]);

                $this->putMetaItem(
                    remoteTaskId: $remoteTaskId,
                    tool: $tool,
                    status: 'PENDING',
                    createdAt: $now,
                    updatedAt: $now,
                );

                $this->putClusterItem(
                    remoteTaskId: $remoteTaskId,
                    agent: $agent,
                    tool: $tool,
                    parameters: $parameters,
                    status: 'PENDING',
                    createdAt: $now,
                    updatedAt: $now,
                );

                try {
                    $response = $this->dispatchTool(
                        baseUrl: $baseUrl,
                        task: $task,
                        agent: $agent,
                        tool: $tool,
                        remoteTaskId: $remoteTaskId,
                        parameters: $parameters,
                    );

                    $this->putMetaItem(
                        remoteTaskId: $remoteTaskId,
                        tool: $tool,
                        status: 'RUNNING',
                        createdAt: $now,
                        updatedAt: now()->utc()->toIso8601String(),
                    );

                    $this->putClusterItem(
                        remoteTaskId: $remoteTaskId,
                        agent: $agent,
                        tool: $tool,
                        parameters: $parameters,
                        status: 'RUNNING',
                        createdAt: $now,
                        updatedAt: now()->utc()->toIso8601String(),
                    );

                    $dispatched[] = [
                        'tool' => $tool,
                        'tool_label' => self::getAvailableTools()[$tool] ?? $tool,
                        'remote_task_id' => $remoteTaskId,
                        'cluster_name' => $agent->cluster_name,
                        'cluster_sort_key' => $this->makeClusterSortKey($agent),
                        'health_status' => data_get($health, 'status'),
                        'agent_response_code' => $response->status(),
                        'agent_response' => $response->json() ?? ['body' => $response->body()],
                        'result_prefix' => $this->makeResultPrefix($remoteTaskId, $agent),
                    ];

                    $this->logInfo('Remote dispatch succeeded.', [
                        'task_id' => $task->task_id,
                        'tool' => $tool,
                        'remote_task_id' => $remoteTaskId,
                        'response_code' => $response->status(),
                        'result_prefix' => $this->makeResultPrefix($remoteTaskId, $agent),
                    ]);
                } catch (Throwable $exception) {
                    $updatedAt = now()->utc()->toIso8601String();

                    $this->putMetaItem(
                        remoteTaskId: $remoteTaskId,
                        tool: $tool,
                        status: 'FAILED',
                        createdAt: $now,
                        updatedAt: $updatedAt,
                        failedClusters: 1,
                    );

                    $this->putClusterItem(
                        remoteTaskId: $remoteTaskId,
                        agent: $agent,
                        tool: $tool,
                        parameters: $parameters,
                        status: 'FAILED',
                        createdAt: $now,
                        updatedAt: $updatedAt,
                    );

                    $failures[] = sprintf(
                        '%s failed to dispatch: %s',
                        self::getAvailableTools()[$tool] ?? $tool,
                        $exception->getMessage(),
                    );

                    $this->logError('Remote dispatch failed.', [
                        'task_id' => $task->task_id,
                        'tool' => $tool,
                        'remote_task_id' => $remoteTaskId,
                        'cluster_name' => $agent->cluster_name,
                        'error' => $exception->getMessage(),
                    ], $exception);
                }
            }

            if ($dispatched === []) {
                throw new RuntimeException(collect($failures)->join(' '));
            }

            $task->update([
                'status' => SecurityTaskStatus::Running,
                'progress' => 20,
                'summary' => [
                    'dispatches' => $dispatched,
                    'dispatch_failures' => $failures,
                ],
                'last_message' => $this->makeDispatchMessage(count($dispatched), count($failures), $agent),
            ]);

            $this->logInfo('Remote task dispatch finished.', [
                'task_id' => $task->task_id,
                'successful_dispatches' => count($dispatched),
                'failed_dispatches' => count($failures),
            ]);
        } catch (Throwable $exception) {
            report($exception);

            $this->logError('Task dispatch failed at top level.', [
                'task_id' => $task->task_id,
                'cluster_agent_id' => $task->cluster_agent_id,
            ], $exception);

            $task->update([
                'status' => SecurityTaskStatus::Failed,
                'progress' => 0,
                'completed_at' => now(),
                'last_message' => $exception->getMessage(),
            ]);
        }
    }

    protected function resolveAgentBaseUrl(ClusterAgent $agent): string
    {
        $baseUrl = trim((string) ($agent->endpoint ?: env('SECURITY_AGENT_BASE_URL', '')));

        if ($baseUrl === '') {
            throw new RuntimeException('Cluster agent endpoint is missing. Populate the endpoint field before dispatching tasks.');
        }

        return rtrim($baseUrl, '/');
    }

    protected function assertAgentHealth(string $baseUrl, ClusterAgent $agent): array
    {
        $this->logInfo('Calling cluster health endpoint.', [
            'cluster_name' => $agent->cluster_name,
            'base_url' => $baseUrl,
            'url' => $baseUrl . '/health/' . rawurlencode((string) $agent->cluster_name),
        ]);

        $response = Http::timeout($this->httpTimeout())
            ->connectTimeout($this->httpConnectTimeout())
            ->acceptJson()
            ->get($baseUrl . '/health/' . rawurlencode((string) $agent->cluster_name));

        if (! $response->successful()) {
            $this->logWarning('Cluster health check returned a non-success response.', [
                'cluster_name' => $agent->cluster_name,
                'status_code' => $response->status(),
                'body' => Str::limit($response->body(), 500),
            ]);

            throw new RuntimeException(sprintf(
                'Health check failed for cluster [%s] with HTTP %d.',
                $agent->cluster_name,
                $response->status(),
            ));
        }

        $this->logInfo('Cluster health check succeeded.', [
            'cluster_name' => $agent->cluster_name,
            'status_code' => $response->status(),
            'body' => $response->json() ?? ['body' => Str::limit($response->body(), 500)],
        ]);

        return $response->json() ?? ['status' => 'ok'];
    }

    protected function dispatchTool(
        string $baseUrl,
        SecurityTask $task,
        ClusterAgent $agent,
        string $tool,
        string $remoteTaskId,
        array $parameters,
    ): Response {
        $endpoint = $this->resolveToolEndpoint($tool);
        $payload = [
            'task_id' => $remoteTaskId,
            'request_id' => $remoteTaskId,
            'cluster' => $agent->cluster_name,
            'cluster_name' => $agent->cluster_name,
            'tool' => $tool,
            'title' => $task->title,
            'notes' => $task->notes,
            'submitted_by' => $task->submitted_by,
            'parameters' => $parameters,
            'result' => [
                'bucket' => (string) config('filesystems.disks.' . env('SCAN_S3_DISK', 's3') . '.bucket'),
                'prefix' => $this->makeResultPrefix($remoteTaskId, $agent),
            ],
        ];

        $response = Http::timeout($this->httpTimeout())
            ->connectTimeout($this->httpConnectTimeout())
            ->acceptJson()
            ->post($baseUrl . $endpoint, $payload);

        if (! $response->successful()) {
            $this->logWarning('Agent API returned a non-success response during tool dispatch.', [
                'tool' => $tool,
                'cluster_name' => $agent->cluster_name,
                'remote_task_id' => $remoteTaskId,
                'endpoint' => $endpoint,
                'status_code' => $response->status(),
                'body' => Str::limit($response->body(), 1000),
            ]);

            throw new RuntimeException(sprintf(
                'Agent rejected %s dispatch with HTTP %d.',
                self::getAvailableTools()[$tool] ?? $tool,
                $response->status(),
            ));
        }

        if (($response->json('success') === false) || ($response->json('status') === 'failed')) {
            throw new RuntimeException((string) ($response->json('message') ?: 'Agent reported a failed dispatch.'));
        }

        return $response;
    }

    protected function resolveToolEndpoint(string $tool): string
    {
        return match ($tool) {
            'checkov' => '/api/tools/scan/checkov',
            'kubebench' => '/api/tools/audit/kube-bench',
            'kubescape' => '/api/tools/audit/kubescape',
            'nmap' => '/api/tools/scan/nmap',
            'rbac-tool' => '/api/tools/audit/rbac-tool',
            default => throw new RuntimeException(sprintf('No agent endpoint is configured for tool [%s].', $tool)),
        };
    }

    protected function buildParameters(string $tool): array
    {
        return [
            'directory' => '',
            'framework' => $tool === 'nmap' ? '' : 'kubernetes',
            'check' => '',
            'skip_check' => '',
            'output_format' => 'json',
            'additional_args' => '',
        ];
    }

    protected function putMetaItem(
        string $remoteTaskId,
        string $tool,
        string $status,
        string $createdAt,
        string $updatedAt,
        int $completedClusters = 0,
        int $expectedClusters = 1,
        int $failedClusters = 0,
    ): void {
        $this->putItem([
            'pk' => $remoteTaskId,
            'sk' => self::TASK_META_SORT_KEY,
            'tool' => $tool,
            'status' => $status,
            'created_at' => $createdAt,
            'updated_at' => $updatedAt,
            'completed_clusters' => $completedClusters,
            'expected_clusters' => $expectedClusters,
            'failed_clusters' => $failedClusters,
        ]);
    }

    protected function putClusterItem(
        string $remoteTaskId,
        ClusterAgent $agent,
        string $tool,
        array $parameters,
        string $status,
        string $createdAt,
        string $updatedAt,
    ): void {
        $this->putItem([
            'pk' => $remoteTaskId,
            'sk' => $this->makeClusterSortKey($agent),
            'tool' => $tool,
            'status' => $status,
            'parameters' => json_encode($parameters, JSON_UNESCAPED_SLASHES),
            'created_at' => $createdAt,
            'updated_at' => $updatedAt,
        ]);
    }

    protected function putItem(array $item): void
    {
        $client = $this->makeDynamoDbClient();
        $marshaler = new Marshaler();

        $this->logInfo('Writing task metadata item to DynamoDB.', [
            'table' => $this->dynamoTableName(),
            'pk' => $item['pk'] ?? null,
            'sk' => $item['sk'] ?? null,
            'status' => $item['status'] ?? null,
            'tool' => $item['tool'] ?? null,
        ]);

        $client->putItem([
            'TableName' => $this->dynamoTableName(),
            'Item' => $marshaler->marshalItem($item),
        ]);
    }

    protected function makeClusterSortKey(ClusterAgent $agent): string
    {
        $prefix = trim((string) ($agent->label ?: $agent->name ?: 'cluster'));

        return $prefix . '#' . $agent->cluster_name;
    }

    protected function makeResultPrefix(string $remoteTaskId, ClusterAgent $agent): string
    {
        return 'result/' . $remoteTaskId . '/' . $agent->cluster_name . '/';
    }

    protected function makeDispatchMessage(int $successCount, int $failureCount, ClusterAgent $agent): string
    {
        return $failureCount > 0
            ? sprintf(
                'Dispatched %d tool(s) to cluster [%s]. %d tool dispatch(es) still need attention.',
                $successCount,
                $agent->cluster_name,
                $failureCount,
            )
            : sprintf(
                'Dispatched %d tool(s) to cluster [%s]. Agent results are expected in S3 and DynamoDB shortly.',
                $successCount,
                $agent->cluster_name,
            );
    }

    protected function dynamoTableName(): string
    {
        return (string) env('SECURITY_TASKS_DYNAMODB_TABLE', 'intern-tasks');
    }

    protected function httpTimeout(): int
    {
        return max(5, (int) env('SECURITY_TASK_HTTP_TIMEOUT_SECONDS', 30));
    }

    protected function httpConnectTimeout(): int
    {
        return max(2, (int) env('SECURITY_TASK_HTTP_CONNECT_TIMEOUT_SECONDS', 10));
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
