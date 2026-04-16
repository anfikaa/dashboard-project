<?php

namespace App\Services;

use App\Support\AwsCredentialFactory;
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;
use App\Models\SecurityTask;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use RuntimeException;

class ScanService
{
    protected ?Collection $availableSampleFilesCache = null;

    protected array $prefixFileCache = [];

    protected bool $s3UnavailableForRequest = false;

    protected array $remoteTaskStatusCache = [];

    public function getToolResultSummaries(array $tools): Collection
    {
        $requestedTools = collect($tools)
            ->filter()
            ->map(fn (string $tool): ?string => $this->normalizeToolName($tool))
            ->filter()
            ->unique()
            ->values();

        if ($requestedTools->isEmpty()) {
            return collect();
        }

        return $this->getRecentS3FilesByTool(env('SCAN_S3_DISK', 's3'), $requestedTools)
            ->map(function (array $file): array {
                try {
                    $findings = $this->parseFile($file);

                    if ($findings->isNotEmpty()) {
                        return $this->summarizeToolFindings($findings, $file);
                    }

                    return $this->makeMissingResultRecord($file);
                } catch (\Throwable $exception) {
                    if ($this->isS3MissingFileException($exception)) {
                        return $this->makeMissingResultRecord($file);
                    }

                    return $this->makeParseErrorRecord($file, $exception);
                }
            })
            ->values();
    }

    public function getAvailableSampleFiles(?array $tools = null): Collection
    {
        if ($tools === null && $this->availableSampleFilesCache instanceof Collection) {
            return $this->availableSampleFilesCache;
        }

        if (env('SCAN_SOURCE', 'local') === 's3') {
            $files = $this->getAvailableS3Files($tools);
        } else {
            $directory = storage_path(env('SCAN_LOCAL_PATH', 'app/scan'));
            $requestedTools = collect($tools ?? [])->filter()->values();

            if (! File::isDirectory($directory)) {
                throw new RuntimeException('Scan sample directory was not found.');
            }

            $files = collect(File::files($directory))
                ->filter(fn ($file): bool => Str::endsWith($file->getFilename(), '.json'))
                ->map(function ($file): array {
                    $tool = $this->detectToolFromFilename($file->getFilename());

                    return [
                        'tool' => $tool,
                        'path' => $file->getPathname(),
                        'filename' => $file->getFilename(),
                        'disk' => null,
                    ];
                })
                ->filter(fn (array $file): bool => filled($file['tool']))
                ->when(
                    $requestedTools->isNotEmpty(),
                    fn (Collection $files): Collection => $files->filter(
                        fn (array $file): bool => $requestedTools->contains($file['tool'])
                    ),
                )
                ->sortBy(['tool', 'filename'])
                ->values();
        }

        if ($tools === null) {
            $this->availableSampleFilesCache = $files;
        }

        return $files;
    }

    protected function getAvailableS3Files(?array $tools): Collection
    {
        $disk = env('SCAN_S3_DISK', 's3');
        $requestedTools = collect($tools ?? array_keys(TaskExecutionService::getAvailableTools()))
            ->filter()
            ->map(fn (string $tool): ?string => $this->normalizeToolName($tool))
            ->filter()
            ->unique()
            ->values();

        $files = $this->getRecentS3FilesByTool($disk, $requestedTools);
        $limited = $this->limitS3Files($files);

        Log::info('Dashboard selected S3 candidate files.', [
            'requested_tools' => $requestedTools->values()->all(),
            'selected_files' => $limited->map(fn (array $file): array => [
                'tool' => $file['tool'] ?? null,
                'path' => $file['path'] ?? null,
                'fallback_paths' => $file['fallback_paths'] ?? [],
                'prefix' => $file['prefix'] ?? null,
            ])->values()->all(),
        ]);

        return $limited;
    }

    public function getS3ResultFiles(string $prefix): Collection
    {
        $disk = env('SCAN_S3_DISK', 's3');

        $files = collect(Storage::disk($disk)->allFiles($prefix))
            ->filter(fn ($file) => Str::endsWith($file, '.json'))
            ->filter(fn ($file) => filled($this->detectToolFromFilename(basename($file))));

        return $this->limitS3Files(
            $files
            ->map(function ($file) use ($disk) {
                $filename = basename($file);
                $tool = $this->detectToolFromFilename($filename);

                return [
                    'tool' => $tool,
                    'path' => $file,
                    'filename' => $filename,
                    'disk' => $disk,
                    'last_modified' => $this->resolveDiskLastModified($disk, $file),
                ];
            })
            ->values()
        );
    }

    public function getS3ResultFilesForTool(string $prefix, string $tool, ?string $clusterName = null): Collection
    {
        $disk = env('SCAN_S3_DISK', 's3');
        $normalizedTool = $this->normalizeToolName($tool);

        if (blank($normalizedTool)) {
            return collect();
        }

        $paths = $this->candidateS3ResultPaths($prefix, $normalizedTool, $clusterName);

        return collect([[
            'tool' => $normalizedTool,
            'path' => $paths[0],
            'filename' => basename($paths[0]),
            'disk' => $disk,
            'last_modified' => 0,
            'fallback_paths' => array_slice($paths, 1),
            'prefix' => rtrim($prefix, '/'),
            'cluster_name' => $clusterName,
        ]]);
    }

    protected function getRecentS3FilesByTool(string $disk, Collection $requestedTools): Collection
    {
        return $this->getRecentResultPrefixesByTool($requestedTools)
            ->map(function (array $dispatch) use ($disk): ?array {
                $tool = $dispatch['tool'];
                $resultPrefix = rtrim((string) $dispatch['result_prefix'], '/');

                if ($resultPrefix === '') {
                    return null;
                }

                $paths = $this->candidateS3ResultPaths($resultPrefix, $tool, $dispatch['cluster_name'] ?? null);

                return [
                    'tool' => $tool,
                    'path' => $paths[0],
                    'filename' => basename($paths[0]),
                    'disk' => $disk,
                    'last_modified' => (int) ($dispatch['completed_at'] ?? 0),
                    'fallback_paths' => array_slice($paths, 1),
                    'prefix' => $resultPrefix,
                    'scan_id' => $this->resolveRemoteScanId(
                        resultPrefix: $resultPrefix,
                        remoteTaskId: $dispatch['remote_task_id'] ?? null,
                        fallbackScanId: $dispatch['scan_id'] ?? null,
                    ),
                    'local_task_id' => $dispatch['local_task_id'] ?? null,
                    'remote_task_id' => $dispatch['remote_task_id'] ?? null,
                    'cluster_name' => $dispatch['cluster_name'] ?? null,
                    'remote_status' => $dispatch['remote_status'] ?? null,
                ];
            })
            ->filter()
            ->values();
    }

    protected function getRecentResultPrefixesByTool(Collection $requestedTools): Collection
    {
        $perToolCandidates = max(1, (int) env('SCAN_S3_PREFIX_CANDIDATES_PER_TOOL', 5));
        $terminalRemoteTasks = $this->getRecentTerminalRemoteTasksByTool($requestedTools);
        $localDispatchIndex = $this->getRecentLocalDispatchIndex();
        $dispatches = $terminalRemoteTasks
            ->map(function (array $remoteTask) use ($localDispatchIndex): ?array {
                $remoteTaskId = (string) ($remoteTask['remote_task_id'] ?? '');
                $localDispatch = $localDispatchIndex->get($remoteTaskId);

                if (! is_array($localDispatch) || blank($localDispatch['result_prefix'] ?? null)) {
                    return null;
                }

                return [
                    'tool' => $remoteTask['tool'] ?? $localDispatch['tool'] ?? null,
                    'result_prefix' => (string) ($localDispatch['result_prefix'] ?? ''),
                    'cluster_name' => (string) ($localDispatch['cluster_name'] ?? ''),
                    'remote_status' => Str::upper((string) ($remoteTask['remote_status'] ?? '')),
                    'scan_id' => $this->resolveRemoteScanId(
                        resultPrefix: (string) ($localDispatch['result_prefix'] ?? ''),
                        remoteTaskId: $remoteTaskId,
                        fallbackScanId: $localDispatch['local_task_id'] ?? null,
                    ),
                    'local_task_id' => (string) ($localDispatch['local_task_id'] ?? ''),
                    'remote_task_id' => $remoteTaskId,
                    'completed_at' => (int) ($remoteTask['completed_at'] ?? 0),
                    'task_id' => $localDispatch['task_id'] ?? null,
                ];
            })
            ->filter();

        if ($dispatches->isEmpty()) {
            Log::warning('Falling back to local completed task dispatches for dashboard S3 candidates because terminal DynamoDB META records were unavailable.', [
                'requested_tools' => $requestedTools->values()->all(),
            ]);

            $dispatches = $this->getFallbackLocalDashboardDispatches($requestedTools);
        }

        return $dispatches
            ->filter(function (?array $dispatch) use ($requestedTools): bool {
                if (! is_array($dispatch)) {
                    return false;
                }

                $remoteStatus = Str::upper((string) ($dispatch['remote_status'] ?? ''));

                return filled($dispatch['tool'])
                    && filled($dispatch['result_prefix'])
                    && in_array($remoteStatus, ['COMPLETED', 'FAILED'], true)
                    && $requestedTools->contains($dispatch['tool']);
            })
            ->sortByDesc(fn (array $dispatch): int => (int) ($dispatch['completed_at'] ?? 0))
            ->groupBy('tool')
            ->flatMap(fn (Collection $group): Collection => $group->take($perToolCandidates))
            ->values();
    }

    protected function getFallbackLocalDashboardDispatches(Collection $requestedTools): Collection
    {
        return $this->getRecentLocalDispatchIndex()
            ->values()
            ->filter(function (array $dispatch) use ($requestedTools): bool {
                $tool = (string) ($dispatch['tool'] ?? '');
                $taskStatus = Str::upper((string) ($dispatch['task_status'] ?? ''));
                $remoteStatus = Str::upper((string) ($dispatch['remote_status'] ?? ''));

                return $requestedTools->contains($tool)
                    && filled($dispatch['result_prefix'] ?? null)
                    && in_array($taskStatus, ['COMPLETED', 'FAILED'], true)
                    && in_array($remoteStatus, ['COMPLETED', 'FAILED'], true);
            })
            ->map(function (array $dispatch): array {
                return [
                    'tool' => $dispatch['tool'] ?? null,
                    'result_prefix' => (string) ($dispatch['result_prefix'] ?? ''),
                    'cluster_name' => (string) ($dispatch['cluster_name'] ?? ''),
                    'remote_status' => Str::upper((string) ($dispatch['remote_status'] ?? '')),
                    'scan_id' => $this->resolveRemoteScanId(
                        resultPrefix: (string) ($dispatch['result_prefix'] ?? ''),
                        remoteTaskId: $dispatch['remote_task_id'] ?? null,
                        fallbackScanId: $dispatch['local_task_id'] ?? null,
                    ),
                    'local_task_id' => (string) ($dispatch['local_task_id'] ?? ''),
                    'remote_task_id' => (string) ($dispatch['remote_task_id'] ?? ''),
                    'completed_at' => (int) ($dispatch['completed_at'] ?? 0),
                    'task_id' => $dispatch['task_id'] ?? null,
                ];
            })
            ->values();
    }

    protected function getRecentTerminalRemoteTasksByTool(Collection $requestedTools): Collection
    {
        $cacheKey = 'scan-service.terminal-remote-tasks.' . md5(json_encode([
            'tools' => $requestedTools->values()->all(),
            'table' => $this->securityTasksDynamoTableName(),
        ]));

        $ttl = max(10, (int) env('SCAN_REMOTE_STATUS_CACHE_TTL_SECONDS', 30));

        return collect(Cache::remember($cacheKey, now()->addSeconds($ttl), function () use ($requestedTools): array {
            try {
                $client = $this->makeDynamoDbClient();
                $marshaler = new Marshaler();
                $records = [];
                $exclusiveStartKey = null;
                $pagesRemaining = max(1, (int) env('SCAN_DYNAMODB_META_SCAN_PAGES', 5));

                do {
                    $params = [
                        'TableName' => $this->securityTasksDynamoTableName(),
                        'FilterExpression' => 'SK = :meta AND #status IN (:completed, :failed)',
                        'ExpressionAttributeNames' => [
                            '#status' => 'status',
                        ],
                        'ExpressionAttributeValues' => [
                            ':meta' => ['S' => 'META'],
                            ':completed' => ['S' => 'COMPLETED'],
                            ':failed' => ['S' => 'FAILED'],
                        ],
                    ];

                    if ($exclusiveStartKey !== null) {
                        $params['ExclusiveStartKey'] = $exclusiveStartKey;
                    }

                    $result = $client->scan($params);

                    foreach ($result['Items'] ?? [] as $item) {
                        $record = $marshaler->unmarshalItem($item);
                        $tool = $this->normalizeToolName((string) ($record['tool'] ?? ''));
                        $status = Str::upper((string) ($record['status'] ?? ''));

                        if (! $requestedTools->contains($tool) || ! in_array($status, ['COMPLETED', 'FAILED'], true)) {
                            continue;
                        }

                        $records[] = [
                            'remote_task_id' => (string) ($record['PK'] ?? ''),
                            'tool' => $tool,
                            'remote_status' => $status,
                            'completed_at' => $this->normalizeTimestamp($record['updated_at'] ?? null)
                                ?? $this->normalizeTimestamp($record['created_at'] ?? null)
                                ?? 0,
                        ];
                    }

                    $exclusiveStartKey = $result['LastEvaluatedKey'] ?? null;
                    $pagesRemaining--;
                } while ($exclusiveStartKey !== null && $pagesRemaining > 0);

                return collect($records)
                    ->filter(fn (array $record): bool => filled($record['remote_task_id']))
                    ->sortByDesc(fn (array $record): int => (int) ($record['completed_at'] ?? 0))
                    ->groupBy('tool')
                    ->flatMap(fn (Collection $group): Collection => $group->unique('remote_task_id')->values())
                    ->values()
                    ->all();
            } catch (\Throwable $exception) {
                Log::warning('Unable to scan terminal META items from DynamoDB for dashboard.', [
                    'table' => $this->securityTasksDynamoTableName(),
                    'error' => $exception->getMessage(),
                ]);

                return [];
            }
        }));
    }

    protected function getRecentLocalDispatchIndex(): Collection
    {
        $maxTasks = max(10, (int) env('SCAN_S3_TASK_LOOKBACK', 50));

        return collect(
            DB::table('security_tasks')
                ->select(['id', 'task_id', 'status', 'summary', 'completed_at', 'updated_at'])
                ->whereNotNull('summary')
                ->orderByDesc('completed_at')
                ->orderByDesc('updated_at')
                ->orderByDesc('id')
                ->limit($maxTasks)
                ->get()
        )
            ->flatMap(function (object $task): Collection {
                $summary = json_decode((string) ($task->summary ?? ''), true);

                if (! is_array($summary)) {
                    return collect();
                }

                return collect($summary['dispatches'] ?? [])
                    ->filter(fn (mixed $dispatch): bool => is_array($dispatch) && filled($dispatch['remote_task_id'] ?? null))
                    ->map(function (array $dispatch) use ($task): array {
                        return [
                            'remote_task_id' => (string) ($dispatch['remote_task_id'] ?? ''),
                            'tool' => $this->normalizeToolName((string) ($dispatch['tool'] ?? '')),
                            'result_prefix' => (string) ($dispatch['result_prefix'] ?? ''),
                            'cluster_name' => (string) ($dispatch['cluster_name'] ?? ''),
                            'remote_status' => Str::upper((string) ($dispatch['remote_status'] ?? '')),
                            'dynamodb_meta_status' => Str::upper((string) ($dispatch['dynamodb_meta_status'] ?? '')),
                            'task_status' => Str::upper((string) ($task->status ?? '')),
                            'local_task_id' => (string) ($task->task_id ?? ''),
                            'task_id' => $task->id,
                            'completed_at' => $this->normalizeTimestamp($task->completed_at ?? null)
                                ?? $this->normalizeTimestamp($task->updated_at ?? null)
                                ?? 0,
                        ];
                    });
            })
            ->sortByDesc(fn (array $dispatch): int => (int) ($dispatch['completed_at'] ?? 0))
            ->unique('remote_task_id')
            ->keyBy('remote_task_id');
    }

    protected function normalizeTimestamp(mixed $value): ?int
    {
        if ($value instanceof Carbon) {
            return $value->timestamp;
        }

        if (is_string($value) && filled($value)) {
            try {
                return Carbon::parse($value)->timestamp;
            } catch (\Throwable) {
                return null;
            }
        }

        return null;
    }

    protected function resolveDashboardRemoteStatus(array $dispatch): string
    {
        $cachedMetaStatus = Str::upper((string) ($dispatch['dynamodb_meta_status'] ?? ''));
        $remoteTaskId = trim((string) ($dispatch['remote_task_id'] ?? ''));

        if ($remoteTaskId !== '') {
            $liveStatus = $this->fetchRemoteTaskMetaStatus($remoteTaskId);

            if (in_array($liveStatus, ['COMPLETED', 'FAILED'], true)) {
                return $liveStatus;
            }
        }

        if (in_array($cachedMetaStatus, ['COMPLETED', 'FAILED'], true)) {
            return $cachedMetaStatus;
        }

        return '';
    }

    protected function fetchRemoteTaskMetaStatus(string $remoteTaskId): ?string
    {
        if (array_key_exists($remoteTaskId, $this->remoteTaskStatusCache)) {
            return $this->remoteTaskStatusCache[$remoteTaskId];
        }

        $cacheKey = 'scan-service.remote-meta-status.' . $remoteTaskId;

        $status = Cache::remember($cacheKey, now()->addSeconds(max(10, (int) env('SCAN_REMOTE_STATUS_CACHE_TTL_SECONDS', 30))), function () use ($remoteTaskId): ?string {
            try {
                $client = $this->makeDynamoDbClient();
                $result = $client->getItem([
                    'TableName' => $this->securityTasksDynamoTableName(),
                    'Key' => [
                        'PK' => ['S' => $remoteTaskId],
                        'SK' => ['S' => 'META'],
                    ],
                    'ConsistentRead' => true,
                ]);

                $item = $result['Item'] ?? null;

                if (! is_array($item)) {
                    return null;
                }

                $record = (new Marshaler())->unmarshalItem($item);
                $status = Str::upper((string) ($record['status'] ?? $record['STATUS'] ?? $record['Status'] ?? ''));

                return $status !== '' ? $status : null;
            } catch (\Throwable $exception) {
                Log::warning('Unable to fetch live DynamoDB META status for dashboard scan.', [
                    'remote_task_id' => $remoteTaskId,
                    'error' => $exception->getMessage(),
                ]);

                return null;
            }
        });

        return $this->remoteTaskStatusCache[$remoteTaskId] = is_string($status) && $status !== '' ? $status : null;
    }

    protected function makeDynamoDbClient(): DynamoDbClient
    {
        $config = [
            'version' => 'latest',
            'region' => env('AWS_DYNAMODB_REGION', env('AWS_DEFAULT_REGION')),
            'retries' => max(0, (int) env('AWS_DYNAMODB_RETRIES', 0)),
            'http' => [
                'connect_timeout' => max(1, (int) env('AWS_DYNAMODB_CONNECT_TIMEOUT', 1)),
                'timeout' => max(1, (int) env('AWS_DYNAMODB_TIMEOUT', 2)),
            ],
        ];

        if (filled(env('AWS_DYNAMODB_ENDPOINT'))) {
            $config['endpoint'] = env('AWS_DYNAMODB_ENDPOINT');
        }

        return new DynamoDbClient(AwsCredentialFactory::applyToConfig($config));
    }

    protected function securityTasksDynamoTableName(): string
    {
        return (string) env('SECURITY_TASKS_DYNAMODB_TABLE', 'intern-tasks');
    }

    protected function resolveRemoteScanId(string $resultPrefix, mixed $remoteTaskId = null, mixed $fallbackScanId = null): string
    {
        $remoteTaskId = is_scalar($remoteTaskId) ? trim((string) $remoteTaskId) : '';

        if ($remoteTaskId !== '') {
            return $remoteTaskId;
        }

        $segments = array_values(array_filter(explode('/', trim($resultPrefix, '/'))));

        if (count($segments) >= 2 && ($segments[0] ?? null) === 'result' && filled($segments[1] ?? null)) {
            return (string) $segments[1];
        }

        return is_scalar($fallbackScanId) && trim((string) $fallbackScanId) !== ''
            ? trim((string) $fallbackScanId)
            : 'unknown-task';
    }

    public function parseFile(array $file): Collection
    {
        if (($file['disk'] ?? null) === env('SCAN_S3_DISK', 's3') && $this->shouldShortCircuitS3Reads()) {
            Log::warning('Skipping S3 parse because scan service circuit breaker is active.', [
                'tool' => $file['tool'] ?? null,
                'path' => $file['path'] ?? null,
            ]);

            return collect();
        }

        $paths = array_values(array_unique(array_filter([
            $file['path'] ?? null,
            ...($file['fallback_paths'] ?? []),
        ])));

        $lastException = null;

        foreach ($paths as $path) {
            try {
                return $this->parseSampleFile($path, $file['tool'], $file['disk'] ?? null);
            } catch (\Throwable $exception) {
                $lastException = $exception;

                if (($file['disk'] ?? null) === env('SCAN_S3_DISK', 's3') && $this->isS3ConnectivityException($exception)) {
                    $this->markS3Unavailable($exception);

                    Log::warning('Stopping S3 parse early because of connectivity/read failure.', [
                        'tool' => $file['tool'] ?? null,
                        'path' => $path,
                        'error' => $exception->getMessage(),
                    ]);

                    return collect();
                }

                if ($this->isS3MissingFileException($exception)) {
                    continue;
                }

                if (! $this->isS3MissingFileException($exception)) {
                    throw $exception;
                }
            }
        }

        $prefix = (string) ($file['prefix'] ?? '');
        $tool = (string) ($file['tool'] ?? '');
        $disk = $file['disk'] ?? null;

        if ($prefix !== '' && $tool !== '' && is_string($disk) && $disk !== '') {
            $discoveredPath = $this->discoverS3ResultPathInPrefix($disk, $prefix, $tool, $paths);

            if ($discoveredPath !== null) {
                try {
                    return $this->parseSampleFile($discoveredPath, $tool, $disk);
                } catch (\Throwable $exception) {
                    if ($this->isS3ConnectivityException($exception)) {
                        $this->markS3Unavailable($exception);

                        Log::warning('Stopping discovered S3 parse because of connectivity/read failure.', [
                            'tool' => $tool,
                            'path' => $discoveredPath,
                            'error' => $exception->getMessage(),
                        ]);

                        return collect();
                    }

                    if ($this->isS3MissingFileException($exception)) {
                        return collect();
                    }

                    throw $exception;
                }
            }
        }

        if ($lastException) {
            throw $lastException;
        }

        return collect();
    }

    protected function candidateS3ResultPaths(string $prefix, string $tool, ?string $clusterName = null): array
    {
        $prefix = rtrim($prefix, '/');
        $tool = $this->normalizeToolName($tool) ?? $tool;
        $clusterName = is_string($clusterName) ? trim($clusterName) : '';

        $candidates = match ($tool) {
            'kubebench' => ['result-kubebench.json', 'result-kube-bench.json', 'result-kube_bench.json', 'result.json'],
            'kubescape' => ['result-kubescape.json', 'result-kube-escape.json', 'result.json'],
            'checkov' => ['result-checkov.json', 'result.json'],
            'nmap' => ['result-nmap.json', 'result.json'],
            'rbac-tool' => ['result-rbac-tool.json', 'result-rbac_tool.json', 'result-rbac.json', 'result.json'],
            default => ['result-' . $tool . '.json', 'result.json'],
        };

        $prefixes = [$prefix];

        if ($clusterName !== '' && ! Str::endsWith($prefix, '/' . $clusterName) && basename($prefix) !== $clusterName) {
            $prefixes[] = $prefix . '/' . $clusterName;
        }

        $parentPrefix = preg_replace('#/[^/]+$#', '', $prefix);

        if (is_string($parentPrefix) && $parentPrefix !== '' && $parentPrefix !== $prefix) {
            $prefixes[] = $parentPrefix;

            if ($clusterName !== '' && ! Str::endsWith($parentPrefix, '/' . $clusterName) && basename($parentPrefix) !== $clusterName) {
                $prefixes[] = $parentPrefix . '/' . $clusterName;
            }
        }

        $paths = [];

        foreach (array_values(array_unique($prefixes)) as $candidatePrefix) {
            foreach (array_values(array_unique($candidates)) as $filename) {
                $paths[] = $candidatePrefix . '/' . $filename;
            }
        }

        return array_values(array_unique($paths));
    }

    protected function summarizeToolFindings(Collection $findings, array $file): array
    {
        $counts = $this->summarize($findings);
        $primary = $findings
            ->sortByDesc(fn (array $finding): int => $this->severityRank((string) ($finding['status_bucket'] ?? 'WARN')))
            ->first() ?? [];
        $statusBucket = $counts['FAIL'] > 0 ? 'FAIL' : ($counts['WARN'] > 0 ? 'WARN' : 'PASS');
        $summary = collect([
            $counts['FAIL'] > 0 ? "{$counts['FAIL']} fail" . ($counts['FAIL'] > 1 ? 's' : '') : null,
            $counts['WARN'] > 0 ? "{$counts['WARN']} warning" . ($counts['WARN'] > 1 ? 's' : '') : null,
            $counts['PASS'] > 0 ? "{$counts['PASS']} pass" . ($counts['PASS'] > 1 ? 'es' : '') : null,
        ])->filter()->implode(', ');

        return [
            'tool' => (string) ($primary['tool'] ?? $file['tool'] ?? 'unknown'),
            'scan_id' => (string) ($file['remote_task_id'] ?? $primary['scan_id'] ?? $file['scan_id'] ?? 'unknown-task'),
            'scan_status' => Str::upper((string) ($file['remote_status'] ?? $primary['scan_status'] ?? 'COMPLETED')),
            'cluster_name' => (string) ($primary['cluster_name'] ?? $file['cluster_name'] ?? 'Unknown cluster'),
            'scanned_at' => $primary['scanned_at'] ?? Carbon::createFromTimestamp((int) ($file['last_modified'] ?? time())),
            'status_bucket' => $statusBucket,
            'description' => trim(implode(' ', array_filter([
                $summary !== '' ? 'Summary: ' . $summary . '.' : null,
                filled($primary['description'] ?? null) ? 'Top finding: ' . Str::limit((string) $primary['description'], 240) : null,
            ]))),
            'recommendation' => (string) ($primary['recommendation'] ?? 'Review the parsed result for this tool in S3 and remediate the reported issues.'),
            'suggestion' => (string) ($primary['suggestion'] ?? 'Use this tool-level summary to decide whether deeper inspection is needed.'),
            'object' => (string) ($primary['object'] ?? $file['cluster_name'] ?? 'Scan result'),
            'metadata' => array_merge($primary['metadata'] ?? [], [
                'object' => $primary['object'] ?? $file['cluster_name'] ?? 'Scan result',
                's3_path' => $file['path'] ?? null,
                's3_prefix' => $file['prefix'] ?? null,
                'result_status' => 'parsed',
                'finding_counts' => $counts,
                'remote_task_id' => $file['remote_task_id'] ?? null,
                'local_task_id' => $file['local_task_id'] ?? null,
            ]),
        ];
    }

    protected function makeMissingResultRecord(array $file): array
    {
        return [
            'tool' => (string) ($file['tool'] ?? 'unknown'),
            'scan_id' => (string) (($file['remote_task_id'] ?? '') ?: ($file['scan_id'] ?? 'unknown-task')),
            'scan_status' => Str::upper((string) ($file['remote_status'] ?? 'COMPLETED')),
            'cluster_name' => (string) ($file['cluster_name'] ?? 'Unknown cluster'),
            'scanned_at' => Carbon::createFromTimestamp((int) ($file['last_modified'] ?? time())),
            'status_bucket' => 'WARN',
            'description' => 'Result file not found in S3 for this tool.',
            'recommendation' => 'Verify the expected S3 object name and prefix for this task result.',
            'suggestion' => 'Confirm whether the worker wrote `result-' . ($file['tool'] ?? 'tool') . '.json` or another supported file name under the task prefix.',
            'object' => (string) ($file['cluster_name'] ?? 'Scan result'),
            'metadata' => [
                'object' => $file['cluster_name'] ?? 'Scan result',
                's3_path' => $file['path'] ?? null,
                's3_prefix' => $file['prefix'] ?? null,
                'result_status' => 'result_file_not_found',
                'fallback_paths' => $file['fallback_paths'] ?? [],
                'remote_task_id' => $file['remote_task_id'] ?? null,
                'local_task_id' => $file['local_task_id'] ?? null,
            ],
        ];
    }

    protected function makeParseErrorRecord(array $file, \Throwable $exception): array
    {
        return [
            'tool' => (string) ($file['tool'] ?? 'unknown'),
            'scan_id' => (string) (($file['remote_task_id'] ?? '') ?: ($file['scan_id'] ?? 'unknown-task')),
            'scan_status' => Str::upper((string) ($file['remote_status'] ?? 'COMPLETED')),
            'cluster_name' => (string) ($file['cluster_name'] ?? 'Unknown cluster'),
            'scanned_at' => Carbon::createFromTimestamp((int) ($file['last_modified'] ?? time())),
            'status_bucket' => 'WARN',
            'description' => 'Result file was found in S3 but could not be parsed.',
            'recommendation' => 'Review the raw JSON result object and update the parser to match the file format.',
            'suggestion' => 'Latest parser error: ' . Str::limit($exception->getMessage(), 180),
            'object' => (string) ($file['cluster_name'] ?? 'Scan result'),
            'metadata' => [
                'object' => $file['cluster_name'] ?? 'Scan result',
                's3_path' => $file['path'] ?? null,
                's3_prefix' => $file['prefix'] ?? null,
                'result_status' => 'parse_error',
                'parse_error' => $exception->getMessage(),
                'remote_task_id' => $file['remote_task_id'] ?? null,
                'local_task_id' => $file['local_task_id'] ?? null,
            ],
        ];
    }

    protected function severityRank(string $bucket): int
    {
        return match (Str::upper($bucket)) {
            'FAIL' => 3,
            'WARN' => 2,
            'PASS' => 1,
            default => 0,
        };
    }

    protected function discoverS3ResultPathInPrefix(string $disk, string $prefix, string $tool, array $excludedPaths = []): ?string
    {
        $files = $this->listS3PrefixFiles($disk, $prefix);

        if ($files->isEmpty()) {
            return null;
        }

        $normalizedTool = $this->normalizeToolName($tool) ?? $tool;
        $excludedLookup = array_flip($excludedPaths);

        $toolTokens = match ($normalizedTool) {
            'kubebench' => ['kubebench', 'kube-bench'],
            'kubescape' => ['kubescape', 'kube-escape'],
            'rbac-tool' => ['rbac-tool', 'rbac_tool', 'rbac'],
            default => [$normalizedTool],
        };

        $preferred = $files
            ->filter(fn (string $path): bool => ! isset($excludedLookup[$path]))
            ->filter(fn (string $path): bool => ! Str::contains(Str::lower(basename($path)), 'health_check'));

        $match = $preferred->first(function (string $path) use ($toolTokens): bool {
            $filename = Str::lower(basename($path));

            foreach ($toolTokens as $token) {
                if (Str::contains($filename, Str::lower($token))) {
                    return true;
                }
            }

            return false;
        });

        if (is_string($match) && $match !== '') {
            return $match;
        }

        $resultJson = $preferred->first(fn (string $path): bool => basename($path) === 'result.json');

        return is_string($resultJson) && $resultJson !== '' ? $resultJson : null;
    }

    protected function listS3PrefixFiles(string $disk, string $prefix): Collection
    {
        if ($this->shouldShortCircuitS3Reads()) {
            return collect();
        }

        $key = $disk . '|' . $prefix;

        if (array_key_exists($key, $this->prefixFileCache)) {
            return collect($this->prefixFileCache[$key]);
        }

        try {
            $files = collect(Storage::disk($disk)->allFiles($prefix))
                ->filter(fn (string $path): bool => Str::endsWith(Str::lower($path), '.json'))
                ->values()
                ->all();
        } catch (\Throwable $exception) {
            if ($this->isS3ConnectivityException($exception)) {
                $this->markS3Unavailable($exception);
            }

            Log::warning('Unable to inspect S3 result prefix.', [
                'disk' => $disk,
                'prefix' => $prefix,
                'error' => $exception->getMessage(),
            ]);

            $files = [];
        }

        $this->prefixFileCache[$key] = $files;

        return collect($files);
    }

    protected function shouldShortCircuitS3Reads(): bool
    {
        if ($this->s3UnavailableForRequest) {
            return true;
        }

        return Cache::has($this->s3UnavailableCacheKey());
    }

    protected function markS3Unavailable(\Throwable $exception): void
    {
        $this->s3UnavailableForRequest = true;

        Cache::put(
            $this->s3UnavailableCacheKey(),
            [
                'message' => Str::limit($exception->getMessage(), 300),
                'at' => now()->toIso8601String(),
            ],
            now()->addSeconds(max(10, (int) env('SCAN_S3_UNAVAILABLE_TTL_SECONDS', 30))),
        );

        Log::warning('Marked S3 as temporarily unavailable for dashboard parsing.', [
            'message' => Str::limit($exception->getMessage(), 300),
            'ttl_seconds' => max(10, (int) env('SCAN_S3_UNAVAILABLE_TTL_SECONDS', 30)),
        ]);
    }

    protected function s3UnavailableCacheKey(): string
    {
        return 'scan-service.s3-unavailable.' . md5(json_encode([
            'disk' => env('SCAN_S3_DISK', 's3'),
            'bucket' => env('AWS_BUCKET'),
            'endpoint' => env('AWS_ENDPOINT'),
        ]));
    }

    protected function isS3ConnectivityException(\Throwable $exception): bool
    {
        $message = Str::lower($exception->getMessage());

        return Str::contains($message, [
            'could not resolve host',
            'connection timed out',
            'timed out',
            'curl error',
            'unable to list contents',
            'aws http error',
        ]);
    }

    protected function isS3MissingFileException(\Throwable $exception): bool
    {
        $message = Str::lower($exception->getMessage());

        return Str::contains($message, [
            'unable to read file from location',
            'nosuchkey',
            'specified key does not exist',
            '404 not found',
        ]);
    }

    public function getNormalizedFindingsForTools(array $tools): Collection
    {
        $files = $this->getAvailableSampleFiles($tools);

        if ($files->isEmpty()) {
            throw new RuntimeException('No matching scan sample files were found for the selected tools.');
        }

        if (env('SCAN_SOURCE', 'local') === 's3') {
            return $files
                ->groupBy(fn (array $file): string => (string) ($file['tool'] ?? 'unknown'))
                ->flatMap(function (Collection $group, string $tool): Collection {
                    foreach ($group as $file) {
                        try {
                            $findings = $this->parseFile($file);

                            if ($findings->isNotEmpty()) {
                                Log::info('Dashboard selected a working S3 result file for tool.', [
                                    'tool' => $tool,
                                    'path' => $file['path'] ?? null,
                                    'fallback_paths' => $file['fallback_paths'] ?? [],
                                    'findings_count' => $findings->count(),
                                ]);

                                return $findings;
                            }
                        } catch (\Throwable $exception) {
                            Log::warning('Skipping scan file because parsing failed.', [
                                'path' => $file['path'] ?? null,
                                'tool' => $file['tool'] ?? null,
                                'disk' => $file['disk'] ?? null,
                                'error' => $exception->getMessage(),
                            ]);
                        }
                    }

                    return collect();
                })
                ->values();
        }

        return $files
            ->flatMap(function (array $file): Collection {
                try {
                    return $this->parseFile($file);
                } catch (\Throwable $exception) {
                    Log::warning('Skipping scan file because parsing failed.', [
                        'path' => $file['path'] ?? null,
                        'tool' => $file['tool'] ?? null,
                        'disk' => $file['disk'] ?? null,
                        'error' => $exception->getMessage(),
                    ]);

                    return collect();
                }
            })
            ->values();
    }

    public function summarize(Collection $findings): array
    {
        $summary = [
            'PASS' => 0,
            'FAIL' => 0,
            'WARN' => 0,
        ];

        foreach ($findings as $finding) {
            $bucket = Str::upper((string) ($finding['status_bucket'] ?? 'WARN'));

            if (array_key_exists($bucket, $summary)) {
                $summary[$bucket]++;
            }
        }

        return $summary;
    }

    protected function parseSampleFile(string $path, ?string $tool = null, ?string $disk = null): Collection
    {
        if ($disk) {
            $content = Storage::disk($disk)->get($path);
        } else {
            if (! File::exists($path)) {
                throw new RuntimeException("Scan sample file does not exist: {$path}");
            }
            $content = File::get($path);
        }

        $payload = json_decode($content, true);

        if (! is_array($payload)) {
            throw new RuntimeException("Scan sample file is not valid JSON: {$path}");
        }

        $payload = $this->normalizePayload($payload);

        $tool ??= $this->detectToolFromFilename(basename($path)) ?? $this->detectToolFromPayload($payload);

        if (blank($tool)) {
            throw new RuntimeException("Unable to detect tool type for scan sample: {$path}");
        }

        $context = [
            'tool' => $tool,
            'filename' => basename($path),
            'scan_id' => $this->resolveScanId($payload, basename($path)),
            'scan_status' => $this->resolveScanStatus($payload),
            'cluster_name' => $payload['cluster_name'] ?? ($payload['stdout']['clusterName'] ?? 'Unknown cluster'),
            'scanned_at' => $this->resolveScannedAt($payload),
            'payload' => $payload,
        ];

        return match ($tool) {
            'kubebench' => $this->parseKubebench($context),
            'kubescape' => $this->parseKubescape($context),
            'checkov' => $this->parseCheckov($context),
            'nmap' => $this->parseNmap($context),
            'rbac-tool' => $this->parseRbacTool($context),
            default => throw new RuntimeException("Tool '{$tool}' is not supported by the sample parser."),
        };
    }

    protected function normalizePayload(array $payload): array
    {
        if (array_is_list($payload)) {
            $entry = collect($payload)
                ->first(fn (mixed $item): bool => is_array($item) && (isset($item['result']) || isset($item['tool']) || isset($item['stdout'])));

            if (is_array($entry)) {
                $payload = $entry;
            }
        }

        if (isset($payload['tool']) && is_scalar($payload['tool'])) {
            $payload['tool'] = $this->normalizeToolName((string) $payload['tool']);
        }

        if (isset($payload['result']) && is_array($payload['result'])) {
            $payload = array_merge($payload['result'], array_diff_key($payload, ['result' => true]));
        }

        $stdout = $payload['stdout'] ?? null;

        if (is_string($stdout) && filled($stdout)) {
            $decodedStdout = json_decode($stdout, true);

            if (! is_array($decodedStdout)) {
                $decodedStdout = $this->extractJsonFromText($stdout);
            }

            if (is_array($decodedStdout)) {
                $payload['stdout'] = $decodedStdout;
            }
        }

        return $payload;
    }

    protected function extractJsonFromText(string $text): ?array
    {
        $start = strpos($text, '{');

        if ($start === false) {
            return null;
        }

        $maxBytes = max(1, (int) env('SCAN_STDOUT_FALLBACK_MAX_BYTES', 2_000_000));
        $jsonLength = strlen($text) - $start;

        if ($jsonLength > $maxBytes) {
            Log::warning('Skipping oversized stdout JSON extraction.', [
                'start_offset' => $start,
                'json_length' => $jsonLength,
                'max_bytes' => $maxBytes,
            ]);

            return null;
        }

        $json = substr($text, $start);
        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : null;
    }

    protected function parseKubebench(array $context): Collection
    {
        $controls = $context['payload']['stdout']['Controls'] ?? [];

        return collect($controls)
            ->flatMap(function (array $control) use ($context): array {
                return collect($control['tests'] ?? [])
                    ->flatMap(function (array $test) use ($context, $control): array {
                        return collect($test['results'] ?? [])
                            ->map(function (array $result, int $index) use ($context, $control, $test): array {
                                $status = Str::upper((string) ($result['status'] ?? 'WARN'));

                                return $this->makeFinding(
                                    context: $context,
                                    statusBucket: $this->mapKubebenchStatus($status),
                                    description: (string) ($result['test_desc'] ?? 'Kube Bench finding'),
                                    recommendation: (string) ($result['remediation'] ?? 'Apply the recommended kube-bench remediation and rerun the scan.'),
                                    object: 'Test ' . ($result['test_number'] ?? ($control['id'] ?? '')),
                                    metadata: [
                                        'tool' => 'kubebench',
                                        'status' => $status,
                                        'control_id' => $control['id'] ?? null,
                                        'section' => $test['section'] ?? null,
                                        'test_number' => $result['test_number'] ?? null,
                                        'actual' => $result['actual_value'] ?? null,
                                        'expected' => $result['expected_result'] ?? null,
                                        'object' => 'Test ' . ($result['test_number'] ?? ($control['id'] ?? '')),
                                        'resource' => $test['section'] ?? null,
                                        'index' => $index,
                                    ],
                                    suggestion: $this->makeSuggestion($this->mapKubebenchStatus($status), 'kubebench'),
                                );
                            })
                            ->all();
                    })
                    ->all();
            })
            ->values();
    }

    protected function parseKubescape(array $context): Collection
    {
        $results = $context['payload']['stdout']['results'] ?? [];

        return collect($results)
            ->flatMap(function (array $resourceResult) use ($context): array {
                $resourceId = (string) ($resourceResult['resourceID'] ?? 'Kubernetes resource');

                return collect($resourceResult['controls'] ?? [])
                    ->map(function (array $control) use ($context, $resourceId): array {
                        $rawStatus = Str::lower((string) data_get($control, 'status.status', 'failed'));
                        $toolSeverity = Str::upper((string) ($control['severity'] ?? 'MEDIUM'));
                        $bucket = $this->mapKubescapeStatus($rawStatus, $toolSeverity);
                        $ruleName = data_get($control, 'rules.0.name');
                        $fixPath = data_get($control, 'rules.0.paths.0.fixPath.path');
                        $fixValue = data_get($control, 'rules.0.paths.0.fixPath.value');

                        return $this->makeFinding(
                            context: $context,
                            statusBucket: $bucket,
                            description: trim(implode(' ', array_filter([
                                $control['name'] ?? 'Kubescape control finding',
                                filled($ruleName) ? "Rule: {$ruleName}." : null,
                            ]))),
                            recommendation: $this->buildKubescapeRecommendation($fixPath, $fixValue),
                            object: $resourceId,
                            metadata: [
                                'tool' => 'kubescape',
                                'status' => Str::upper($rawStatus),
                                'tool_severity' => $toolSeverity,
                                'control_id' => $control['controlID'] ?? null,
                                'rule_name' => $ruleName,
                                'fix_path' => $fixPath,
                                'fix_value' => $fixValue,
                                'object' => $resourceId,
                                'resource' => $resourceId,
                                'name' => $control['name'] ?? null,
                            ],
                            suggestion: $this->makeSuggestion($bucket, 'kubescape'),
                        );
                    })
                    ->all();
            })
            ->values();
    }

    protected function parseCheckov(array $context): Collection
    {
        $results = $context['payload']['stdout']['results'] ?? [];
        $groups = [
            'failed_checks' => 'FAIL',
            'passed_checks' => 'PASS',
            'skipped_checks' => 'WARN',
        ];

        return collect($groups)
            ->flatMap(function (string $bucket, string $group) use ($context, $results): array {
                return collect($results[$group] ?? [])
                    ->map(function (array $check) use ($context, $bucket, $group): array {
                        $resource = (string) ($check['resource'] ?? 'Kubernetes manifest resource');
                        $guideline = $check['guideline'] ?? null;
                        $details = collect($check['details'] ?? [])
                            ->filter(fn ($detail): bool => is_string($detail) && filled($detail))
                            ->implode(' ');

                        return $this->makeFinding(
                            context: $context,
                            statusBucket: $bucket,
                            description: (string) ($check['check_name'] ?? 'Checkov policy finding'),
                            recommendation: $guideline ?: ($details ?: 'Review the manifest against the failed Checkov policy and update the resource configuration.'),
                            object: $resource,
                            metadata: [
                                'tool' => 'checkov',
                                'status' => Str::upper((string) data_get($check, 'check_result.result', $group)),
                                'control_id' => $check['check_id'] ?? null,
                                'section' => $context['payload']['stdout']['check_type'] ?? null,
                                'resource' => $resource,
                                'object' => $resource,
                                'file_path' => $check['file_path'] ?? null,
                                'guideline' => $guideline,
                                'details' => $check['details'] ?? [],
                            ],
                            suggestion: $this->makeSuggestion($bucket, 'checkov'),
                        );
                    })
                    ->all();
            })
            ->values();
    }

    protected function parseRbacTool(array $context): Collection
    {
        $findings = $context['payload']['stdout']['Findings'] ?? [];

        return collect($findings)
            ->map(function (array $entry) use ($context): array {
                $subject = $entry['Subject'] ?? [];
                $finding = $entry['Finding'] ?? [];
                $rawSeverity = Str::upper((string) ($finding['Severity'] ?? 'HIGH'));
                $bucket = $this->mapSeverityToBucket($rawSeverity);
                $subjectLabel = collect([
                    $subject['kind'] ?? null,
                    filled($subject['namespace'] ?? null) ? $subject['namespace'] : null,
                    $subject['name'] ?? null,
                ])->filter()->implode('.');

                return $this->makeFinding(
                    context: $context,
                    statusBucket: $bucket,
                    description: (string) ($finding['Message'] ?? 'RBAC finding'),
                    recommendation: (string) ($finding['Recommendation'] ?? 'Review the RBAC permissions attached to the subject and reduce unnecessary access.'),
                    object: $subjectLabel ?: 'RBAC subject',
                    metadata: [
                        'tool' => 'rbac-tool',
                        'status' => $rawSeverity,
                        'tool_severity' => $rawSeverity,
                        'rule_name' => $finding['RuleName'] ?? null,
                        'rule_uuid' => $finding['RuleUuid'] ?? null,
                        'references' => $finding['References'] ?? [],
                        'subject_kind' => $subject['kind'] ?? null,
                        'subject_name' => $subject['name'] ?? null,
                        'subject_namespace' => $subject['namespace'] ?? null,
                        'object' => $subjectLabel ?: 'RBAC subject',
                        'resource' => $subjectLabel ?: 'RBAC subject',
                    ],
                    suggestion: $this->makeSuggestion($bucket, 'rbac-tool'),
                );
            })
            ->values();
    }

    protected function parseNmap(array $context): Collection
    {
        return collect($context['payload']['stdout'] ?? [])
            ->flatMap(function ($scanEntry, string $scanKey) use ($context): array {
                if (!is_array($scanEntry)) {
                    return [];
                }

                $nmapRun = $scanEntry['nmaprun'] ?? [];
                $host = $nmapRun['host'] ?? [];
                $address = data_get($host, 'address.@addr');
                $hostname = data_get($host, 'hostnames.hostname.@name');
                $ports = data_get($host, 'ports.port', []);
                $ports = is_array($ports) && array_is_list($ports) ? $ports : (filled($ports) ? [$ports] : []);

                return collect($ports)
                    ->filter(fn (array $port): bool => Str::lower((string) data_get($port, 'state.@state')) === 'open')
                    ->map(function (array $port) use ($context, $scanKey, $address, $hostname, $nmapRun): array {
                        $portId = (string) data_get($port, '@portid', 'unknown');
                        $protocol = Str::lower((string) data_get($port, '@protocol', 'tcp'));
                        $service = data_get($port, 'service.@name');
                        $objectLabel = trim(implode(' ', array_filter([
                            filled($hostname) ? $hostname : null,
                            filled($address) ? "({$address})" : null,
                            "{$protocol}/{$portId}",
                        ])));

                        return $this->makeFinding(
                            context: $context,
                            statusBucket: 'WARN',
                            description: trim(implode(' ', array_filter([
                                "Open {$protocol} port {$portId} detected",
                                filled($service) ? "running service {$service}." : 'with no resolved service name.',
                            ]))),
                            recommendation: "Validate whether {$protocol}/{$portId}" . (filled($service) ? " ({$service})" : '') . ' must be exposed. Restrict the service with firewall rules, security groups, or host-based access controls if it is not required.',
                            object: $objectLabel,
                            metadata: [
                                'tool' => 'nmap',
                                'status' => 'OPEN',
                                'section' => 'network',
                                'resource' => $objectLabel,
                                'object' => $objectLabel,
                                'host_identifier' => $scanKey,
                                'ip_address' => $address,
                                'hostname' => $hostname,
                                'port' => $portId,
                                'protocol' => $protocol,
                                'service_name' => $service,
                                'scanner' => data_get($nmapRun, '@scanner'),
                                'scan_arguments' => data_get($nmapRun, '@args'),
                            ],
                            suggestion: $this->makeSuggestion('WARN', 'nmap'),
                        );
                    })
                    ->all();
            })
            ->values();
    }

    protected function makeFinding(array $context, string $statusBucket, string $description, string $recommendation, string $object, array $metadata, string $suggestion): array
    {
        return [
            'tool' => $context['tool'],
            'scan_id' => $context['scan_id'],
            'scan_status' => $context['scan_status'],
            'cluster_name' => $context['cluster_name'],
            'scanned_at' => $context['scanned_at'],
            'status_bucket' => $statusBucket,
            'description' => $description,
            'recommendation' => $recommendation,
            'suggestion' => $suggestion,
            'object' => $object,
            'metadata' => array_merge($metadata, [
                'scan_id' => $context['scan_id'],
                'scan_status' => $context['scan_status'],
                'cluster_name' => $context['cluster_name'],
                'sample_file' => $context['filename'],
                'scanned_at' => $context['scanned_at']->toIso8601String(),
            ]),
        ];
    }

    protected function resolveScannedAt(array $payload): Carbon
    {
        foreach (['timestamp', 'execution_time'] as $key) {
            if (filled($payload[$key] ?? null)) {
                return Carbon::parse($payload[$key]);
            }
        }

        return now();
    }

    protected function resolveScanId(array $payload, string $filename): string
    {
        foreach (['id', 'scan_id', 'task_id', 'pk', 'PK'] as $key) {
            $value = $payload[$key] ?? null;

            if (is_string($value) && filled($value)) {
                return $value;
            }
        }

        return pathinfo($filename, PATHINFO_FILENAME);
    }

    protected function resolveScanStatus(array $payload): string
    {
        $status = $payload['status'] ?? null;

        if (is_string($status) && filled($status)) {
            return Str::upper($status);
        }

        if (($payload['success'] ?? null) === true || (int) ($payload['return_code'] ?? 1) === 0) {
            return 'COMPLETED';
        }

        return 'FAILED';
    }

    protected function detectToolFromFilename(string $filename): ?string
    {
        $lower = Str::lower($filename);

        if (preg_match('/^result-(.+)\.json$/', $lower, $matches) === 1) {
            return $this->normalizeToolName($matches[1]);
        }

        return match (true) {
            Str::contains($lower, 'kubebench') => 'kubebench',
            Str::contains($lower, 'kubescape') => 'kubescape',
            Str::contains($lower, 'checkov') => 'checkov',
            Str::contains($lower, 'nmap') => 'nmap',
            Str::contains($lower, 'rbac') => 'rbac-tool',
            default => null,
        };
    }

    protected function detectToolFromPayload(array $payload): ?string
    {
        $tool = $this->normalizeToolName((string) ($payload['tool'] ?? ''));

        if (filled($tool)) {
            return $tool;
        }

        $stdout = $payload['stdout'] ?? [];

        return match (true) {
            isset($stdout['Controls'], $stdout['Totals']) => 'kubebench',
            isset($stdout['summaryDetails'], $stdout['results']) => 'kubescape',
            isset($stdout['summary'], $stdout['results']) && isset($stdout['check_type']) => 'checkov',
            collect($stdout)->contains(fn ($entry): bool => is_array($entry) && isset($entry['nmaprun'])) => 'nmap',
            isset($stdout['Findings'], $stdout['Stats']) => 'rbac-tool',
            default => null,
        };
    }

    protected function mapKubebenchStatus(string $status): string
    {
        return match ($status) {
            'PASS' => 'PASS',
            'FAIL' => 'FAIL',
            default => 'WARN',
        };
    }

    protected function mapKubescapeStatus(string $rawStatus, string $severity): string
    {
        if ($rawStatus === 'passed') {
            return 'PASS';
        }

        return $this->mapSeverityToBucket($severity);
    }

    protected function mapSeverityToBucket(string $severity): string
    {
        return match (Str::upper($severity)) {
            'CRITICAL', 'HIGH' => 'FAIL',
            'MEDIUM', 'LOW', 'WARN', 'WARNING' => 'WARN',
            'PASS', 'PASSED' => 'PASS',
            default => 'WARN',
        };
    }

    protected function buildKubescapeRecommendation(?string $fixPath, ?string $fixValue): string
    {
        if (filled($fixPath) && filled($fixValue)) {
            return "Set {$fixPath} to {$fixValue} on the affected Kubernetes resource, then rerun the scan.";
        }

        if (filled($fixPath)) {
            return "Review the resource configuration and update {$fixPath} according to the Kubescape control guidance.";
        }

        return 'Review the failing Kubescape control and harden the affected resource according to the control guidance.';
    }

    protected function makeSuggestion(string $bucket, string $tool): string
    {
        return match ($bucket) {
            'FAIL' => "Prioritize this {$tool} finding for remediation, then rerun the scan to confirm the fix.",
            'WARN' => "Review this {$tool} finding with the platform owner and decide whether remediation or an exception is appropriate.",
            default => "This {$tool} check is currently compliant. Keep it monitored in future scans.",
        };
    }

    protected function limitS3Files(Collection $files): Collection
    {
        $maxFiles = max(1, (int) env('SCAN_S3_MAX_FILES', 200));
        $maxFilesPerTool = max(1, (int) env('SCAN_S3_MAX_FILES_PER_TOOL', 1));

        return $files
            ->filter(fn (array $file): bool => filled($file['tool'] ?? null))
            ->groupBy(fn (array $file): string => (string) $file['tool'])
            ->flatMap(function (Collection $group) use ($maxFilesPerTool): Collection {
                return $group
                    ->sortByDesc(fn (array $file): int => (int) ($file['last_modified'] ?? 0))
                    ->take($maxFilesPerTool)
                    ->values();
            })
            ->sortBy([
                ['last_modified', 'desc'],
                ['tool', 'asc'],
            ])
            ->take($maxFiles)
            ->values();
    }

    protected function normalizeToolName(string $tool): ?string
    {
        $value = Str::of($tool)
            ->trim()
            ->lower()
            ->replace('_', '-')
            ->value();

        if ($value === '') {
            return null;
        }

        return match ($value) {
            'kube-bench', 'kubebench' => 'kubebench',
            'kube-escape', 'kubescape' => 'kubescape',
            'rbac', 'rbac-tool' => 'rbac-tool',
            'n-map', 'nmap' => 'nmap',
            'check-ov', 'checkov' => 'checkov',
            default => $value,
        };
    }
}
