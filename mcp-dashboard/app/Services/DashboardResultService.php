<?php

namespace App\Services;

use App\Models\SecurityTaskResult;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class DashboardResultService
{
    protected const CACHE_VERSION = '2026-04-14-dashboard-db-v3';

    protected ?Collection $requestFindingsCache = null;

    public function __construct(
        protected ScanService $scanService,
    ) {}

    public function summarize(?array $filters = null): array
    {
        return $this->scanService->summarize($this->getFilteredFindings($filters));
    }

    public function getTopFindings(?array $filters = null, ?string $search = null): Collection
    {
        $records = $this->getFilteredFindings($filters)
            ->filter(fn (array $finding): bool => in_array($finding['status_bucket'], ['FAIL', 'WARN'], true))
            ->map(fn (array $finding): array => $this->transformFinding($finding))
            ->sortBy([
                ['severity_rank', 'desc'],
                ['scanned_at', 'desc'],
            ])
            ->values();

        if (blank($search)) {
            return $records;
        }

        $needle = Str::lower(trim($search));

        return $records
            ->filter(function (array $finding) use ($needle): bool {
                $haystack = Str::lower(implode(' ', array_filter([
                    $finding['scan_id'] ?? '',
                    $finding['task_identifier'] ?? '',
                    $finding['source_tool'] ?? '',
                    $finding['cluster_name'] ?? '',
                    $finding['scan_status'] ?? '',
                    $finding['scan_datetime'] ?? '',
                    $finding['control_id'] ?? '',
                    $finding['test_number'] ?? '',
                    $finding['section'] ?? '',
                    $finding['scan_finding'] ?? '',
                    $finding['recommendation'] ?? '',
                    $finding['suggestion'] ?? '',
                    $finding['object_label'] ?? '',
                    $finding['actual'] ?? '',
                    $finding['expected'] ?? '',
                ])));

                return Str::contains($haystack, $needle);
            })
            ->values();
    }

    public function getDashboardOptions(string $field): array
    {
        return $this->allFindings()
            ->pluck($field)
            ->filter(fn ($value): bool => filled($value))
            ->unique()
            ->sort()
            ->values()
            ->mapWithKeys(fn (string $value): array => [$value => $value])
            ->all();
    }

    protected function getFilteredFindings(?array $filters = null): Collection
    {
        $filters ??= [];

        return $this->allFindings()
            ->when(
                filled($filters['task_identifier'] ?? null),
                fn (Collection $findings): Collection => $findings->where('scan_id', $filters['task_identifier'])->values(),
            )
            ->when(
                filled($filters['source_tool'] ?? null),
                fn (Collection $findings): Collection => $findings->where('tool', $filters['source_tool'])->values(),
            )
            ->when(
                filled($filters['cluster_name'] ?? null),
                fn (Collection $findings): Collection => $findings->where('cluster_name', $filters['cluster_name'])->values(),
            );
    }

    protected function allFindings(): Collection
    {
        if ($this->requestFindingsCache instanceof Collection) {
            return $this->requestFindingsCache;
        }

        $ttl = max(1, (int) env('SCAN_CACHE_TTL_SECONDS', 300));
        $cacheKey = 'dashboard.findings.' . md5(json_encode([
            'version' => self::CACHE_VERSION,
            'results_updated_at' => SecurityTaskResult::query()->max('updated_at'),
            'scan_source' => env('SCAN_SOURCE', 'local'),
            'disk' => env('SCAN_S3_DISK', 's3'),
            'prefix' => env('SCAN_S3_PREFIX', 'result'),
        ]));

        $items = Cache::remember($cacheKey, now()->addSeconds($ttl), function (): array {
            $preferS3 = env('SCAN_SOURCE', 'local') === 's3';
            $databaseCount = SecurityTaskResult::query()->count();
            $cacheTtl = max(1, (int) env('SCAN_CACHE_TTL_SECONDS', 300));

            Log::info('Dashboard findings refresh started.', [
                'prefer_s3' => $preferS3,
                'database_results_count' => $databaseCount,
                'cache_ttl_seconds' => $cacheTtl,
            ]);

            if (! $preferS3) {
                $databaseFindings = $this->loadFindingsFromDatabase();

                if ($databaseFindings->isNotEmpty()) {
                    Log::info('Dashboard served findings from database only.', [
                        'database_findings_count' => $databaseFindings->count(),
                    ]);

                    return $databaseFindings
                        ->map(fn (array $finding): array => $this->serializeFinding($finding))
                        ->values()
                        ->all();
                }
            }

            try {
                $s3Findings = $this->scanService
                    ->getNormalizedFindingsForTools(array_keys(TaskExecutionService::getAvailableTools()))
                    ->map(fn (array $finding): array => $this->serializeFinding($finding))
                    ->values();

                if ($s3Findings->isNotEmpty()) {
                    Log::info('Dashboard served findings from S3 parsing.', [
                        's3_findings_count' => $s3Findings->count(),
                    ]);

                    return $s3Findings->all();
                }

                Log::warning('Dashboard S3 parsing completed but returned no findings.', [
                    'database_results_count' => $databaseCount,
                ]);
            } catch (Throwable) {
                // Fall back to database below.
            }

            $databaseFindings = $this->loadFindingsFromDatabase();

            if ($databaseFindings->isNotEmpty()) {
                Log::info('Dashboard fell back to database findings after S3 attempt.', [
                    'database_findings_count' => $databaseFindings->count(),
                ]);

                return $databaseFindings
                    ->map(fn (array $finding): array => $this->serializeFinding($finding))
                        ->values()
                        ->all();
            }

            $rawFindings = $this->loadRawStdoutFallbackFindings();

            if ($rawFindings->isNotEmpty()) {
                Log::info('Dashboard served raw stdout preview fallback findings.', [
                    'raw_findings_count' => $rawFindings->count(),
                ]);

                return $rawFindings
                    ->map(fn (array $finding): array => $this->serializeFinding($finding))
                    ->values()
                    ->all();
            }

            Log::warning('Dashboard has no findings available from either S3 or database.', [
                'database_results_count' => $databaseCount,
            ]);

            return [];
        });

        return $this->requestFindingsCache = collect($items)
            ->map(fn (array $finding): array => $this->hydrateFinding($finding))
            ->values();
    }

    protected function loadFindingsFromDatabase(): Collection
    {
        return SecurityTaskResult::query()
            ->latest('scanned_at')
            ->get()
            ->map(fn (SecurityTaskResult $result): array => $this->mapDatabaseFinding($result))
            ->values();
    }

    protected function loadRawStdoutFallbackFindings(): Collection
    {
        $maxTasks = max(5, (int) env('DASHBOARD_RAW_TASK_LOOKBACK', 20));

        return collect(
            DB::table('security_tasks')
                ->select(['task_id', 'status', 'summary', 'completed_at', 'updated_at'])
                ->whereNotNull('summary')
                ->orderByDesc('completed_at')
                ->orderByDesc('updated_at')
                ->limit($maxTasks)
                ->get()
        )
            ->flatMap(function (object $task): Collection {
                $summary = json_decode((string) ($task->summary ?? ''), true);

                if (! is_array($summary)) {
                    return collect();
                }

                return collect($summary['dispatches'] ?? [])
                    ->filter(fn (mixed $dispatch): bool => is_array($dispatch))
                    ->map(function (array $dispatch) use ($task): ?array {
                        $agentResponse = collect($dispatch['agent_response'] ?? [])
                            ->first(fn (mixed $entry): bool => is_array($entry) && is_array($entry['result'] ?? null));

                        $result = is_array($agentResponse) ? ($agentResponse['result'] ?? null) : null;

                        if (! is_array($result)) {
                            return null;
                        }

                        $stdoutPreview = $this->makeStdoutPreview($result['stdout'] ?? null);

                        if (blank($stdoutPreview)) {
                            return null;
                        }

                        $scanStatus = Str::upper((string) ($dispatch['remote_status'] ?? $dispatch['status'] ?? $task->status ?? 'COMPLETED'));
                        $statusBucket = $scanStatus === 'FAILED' ? 'FAIL' : 'WARN';
                        $tool = (string) ($dispatch['tool'] ?? 'unknown');
                        $clusterName = (string) ($dispatch['cluster_name'] ?? 'Unknown cluster');
                        $scannedAt = $dispatch['imported_at']
                            ?? $dispatch['completed_at']
                            ?? $task->completed_at
                            ?? $task->updated_at;

                        return [
                            'tool' => $tool,
                            'scan_id' => (string) ($task->task_id ?? 'unknown-task'),
                            'scan_status' => $scanStatus,
                            'cluster_name' => $clusterName,
                            'scanned_at' => $this->normalizeScannedAt($scannedAt),
                            'status_bucket' => $statusBucket,
                            'description' => $stdoutPreview,
                            'recommendation' => 'Raw stdout preview from the latest task result. Open the task detail or S3 result file for the full output.',
                            'suggestion' => 'Use this preview as a temporary fallback while structured parsing from S3 is still being fixed.',
                            'object' => 'Raw stdout preview',
                            'metadata' => [
                                'tool' => $tool,
                                'scan_id' => $task->task_id,
                                'scan_status' => $scanStatus,
                                'cluster_name' => $clusterName,
                                'object' => 'Raw stdout preview',
                                'raw_stdout_preview' => $stdoutPreview,
                                'remote_task_id' => $dispatch['remote_task_id'] ?? null,
                                'result_prefix' => $dispatch['result_prefix'] ?? null,
                            ],
                        ];
                    })
                    ->filter()
                    ->values();
            })
            ->values();
    }

    protected function mapDatabaseFinding(SecurityTaskResult $result): array
    {
        $metadata = is_array($result->metadata) ? $result->metadata : [];
        $bucket = Str::upper((string) ($metadata['status_bucket'] ?? $result->severity ?? 'WARN'));
        $scanStatus = $metadata['scan_status']
            ?? (Str::contains(Str::lower((string) $result->scan_finding), 'execution failed') ? 'FAILED' : 'COMPLETED');

        return [
            'tool' => (string) ($result->source_tool ?? $metadata['tool'] ?? 'unknown'),
            'scan_id' => (string) ($result->task_identifier ?? $metadata['scan_id'] ?? 'unknown-task'),
            'scan_status' => Str::upper((string) $scanStatus),
            'cluster_name' => (string) ($result->cluster_name ?? $metadata['cluster_name'] ?? 'Unknown cluster'),
            'scanned_at' => $this->normalizeScannedAt($result->scanned_at),
            'status_bucket' => $bucket,
            'description' => (string) ($result->scan_finding ?? 'Finding generated from imported scan result.'),
            'recommendation' => (string) ($result->recommendation ?? 'Review the reported issue and apply the recommended control.'),
            'suggestion' => (string) ($result->suggestion ?? 'Review this finding with the security team and remediate as needed.'),
            'object' => (string) ($metadata['object'] ?? $metadata['resource'] ?? $metadata['name'] ?? $result->cluster_name ?? 'Finding context'),
            'metadata' => array_merge($metadata, [
                'scan_id' => $metadata['scan_id'] ?? $result->task_identifier,
                'scan_status' => Str::upper((string) $scanStatus),
                'cluster_name' => $metadata['cluster_name'] ?? $result->cluster_name,
                'object' => $metadata['object'] ?? $metadata['resource'] ?? $metadata['name'] ?? $result->cluster_name,
            ]),
        ];
    }

    protected function transformFinding(array $finding): array
    {
        $metadata = $finding['metadata'] ?? [];
        $bucket = $finding['status_bucket'];

        return [
            'key' => implode('-', array_filter([
                $finding['scan_id'] ?? null,
                $finding['tool'] ?? null,
                $finding['cluster_name'] ?? null,
                $metadata['sample_file'] ?? null,
                $metadata['control_id'] ?? null,
                $metadata['test_number'] ?? null,
                $metadata['rule_uuid'] ?? null,
                md5(($finding['description'] ?? '') . ($finding['object'] ?? '')),
            ])),
            'scan_id' => $finding['scan_id'] ?? ($metadata['scan_id'] ?? 'sample-scan'),
            'task_identifier' => $finding['scan_id'] ?? ($metadata['scan_id'] ?? 'sample-scan'),
            'source_tool' => $finding['tool'],
            'cluster_name' => $finding['cluster_name'],
            'scan_status' => $finding['scan_status'] ?? ($metadata['scan_status'] ?? 'UNKNOWN'),
            'scan_datetime' => $finding['scanned_at']?->format('d M Y H:i:s'),
            'control_id' => $metadata['control_id'] ?? null,
            'test_number' => $metadata['test_number'] ?? null,
            'section' => $metadata['section'] ?? null,
            'scan_finding' => $finding['description'],
            'recommendation' => $finding['recommendation'],
            'suggestion' => $finding['suggestion'],
            'severity' => $bucket,
            'status' => $bucket,
            'severity_rank' => match ($bucket) {
                'FAIL' => 3,
                'WARN' => 2,
                default => 1,
            },
            'actual' => $metadata['actual'] ?? null,
            'expected' => $metadata['expected'] ?? null,
            'object_label' => $this->resolveObjectLabel($metadata),
            'scanned_at' => $finding['scanned_at']?->timestamp ?? 0,
        ];
    }

    protected function resolveObjectLabel(array $metadata): string
    {
        foreach (['object', 'resource', 'resource_name', 'object_name', 'name'] as $key) {
            $value = $metadata[$key] ?? null;

            if (is_string($value) && filled($value)) {
                return $value;
            }
        }

        return collect([
            filled($metadata['control_id'] ?? null) ? 'Control ' . $metadata['control_id'] : null,
            filled($metadata['test_number'] ?? null) ? 'Test ' . $metadata['test_number'] : null,
            filled($metadata['rule_name'] ?? null) ? 'Rule ' . $metadata['rule_name'] : null,
            filled($metadata['file_path'] ?? null) ? 'File ' . $metadata['file_path'] : null,
        ])->filter()->join(' | ') ?: 'Finding context';
    }

    protected function makeStdoutPreview(mixed $stdout): ?string
    {
        if (is_array($stdout)) {
            $stdout = json_encode($stdout, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        }

        if (! is_string($stdout) || blank(trim($stdout))) {
            return null;
        }

        $normalized = preg_replace('/\s+/u', ' ', trim($stdout));

        if (! is_string($normalized) || $normalized === '') {
            return null;
        }

        return Str::words($normalized, 500, ' ...');
    }

    protected function serializeFinding(array $finding): array
    {
        $finding['scanned_at'] = $this->normalizeScannedAt($finding['scanned_at'] ?? null)?->toIso8601String();

        return $finding;
    }

    protected function hydrateFinding(array $finding): array
    {
        $finding['scanned_at'] = $this->normalizeScannedAt($finding['scanned_at'] ?? null);

        return $finding;
    }

    protected function normalizeScannedAt(mixed $value): ?Carbon
    {
        if ($value instanceof Carbon) {
            return $value;
        }

        if (filled($value)) {
            return Carbon::parse($value);
        }

        return null;
    }
}
