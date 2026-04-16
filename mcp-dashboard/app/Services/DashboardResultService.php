<?php

namespace App\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class DashboardResultService
{
    protected const CACHE_VERSION = '2026-04-16-dashboard-remote-first-v1';

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
            'results_updated_at' => DB::table('security_task_results')->max('updated_at'),
            'tasks_updated_at' => DB::table('security_tasks')->max('updated_at'),
            'tasks_completed_at' => DB::table('security_tasks')->max('completed_at'),
            'tasks_count' => DB::table('security_tasks')->count(),
            'scan_source' => env('SCAN_SOURCE', 'local'),
            'disk' => env('SCAN_S3_DISK', 's3'),
            'prefix' => env('SCAN_S3_PREFIX', 'result'),
        ]));

        $items = Cache::remember($cacheKey, now()->addSeconds($ttl), function (): array {
            $databaseCount = DB::table('security_task_results')->count();
            $taskCount = DB::table('security_tasks')->count();
            $cacheTtl = max(1, (int) env('SCAN_CACHE_TTL_SECONDS', 300));
            $preferS3 = env('SCAN_SOURCE', 'local') === 's3';

            Log::info('Dashboard findings refresh started.', [
                'prefer_s3' => $preferS3,
                'database_results_count' => $databaseCount,
                'security_tasks_count' => $taskCount,
                'cache_ttl_seconds' => $cacheTtl,
            ]);

            if ($preferS3) {
                $remoteFindings = $this->loadRemoteFindings();

                if ($remoteFindings->isNotEmpty()) {
                    Log::info('Dashboard served tool summaries directly from DynamoDB/S3.', [
                        'remote_records_count' => $remoteFindings->count(),
                    ]);

                    return $remoteFindings
                        ->map(fn (array $finding): array => $this->serializeFinding($finding))
                        ->values()
                        ->all();
                }
            }

            $databaseFindings = $this->loadCachedFindingsFromDatabase();

            if ($databaseFindings->isNotEmpty()) {
                Log::info('Dashboard served findings from SQLite cache fallback.', [
                    'database_findings_count' => $databaseFindings->count(),
                ]);

                return $databaseFindings
                    ->map(fn (array $finding): array => $this->serializeFinding($finding))
                    ->values()
                    ->all();
            }

            Log::warning('Dashboard has no findings available from either S3 or database.', [
                'database_results_count' => $databaseCount,
                'security_tasks_count' => $taskCount,
            ]);

            return [];
        });

        return $this->requestFindingsCache = collect($items)
            ->map(fn (array $finding): array => $this->hydrateFinding($finding))
            ->filter(fn (array $finding): bool => in_array(Str::upper((string) ($finding['scan_status'] ?? '')), ['COMPLETED', 'FAILED'], true))
            ->values();
    }

    protected function loadRemoteFindings(): Collection
    {
        try {
            return $this->scanService
                ->getToolResultSummaries(array_keys(TaskExecutionService::getAvailableTools()))
                ->values();
        } catch (Throwable $exception) {
            Log::warning('Dashboard remote findings read failed.', [
                'error' => $exception->getMessage(),
            ]);

            return collect();
        }
    }

    protected function loadCachedFindingsFromDatabase(): Collection
    {
        return $this->aggregateFindingsByScanTool(
            collect(
            DB::table('security_task_results')
                ->select([
                    'task_identifier',
                    'source_tool',
                    'cluster_name',
                    'severity',
                    'scan_finding',
                    'recommendation',
                    'suggestion',
                    'metadata',
                    'scanned_at',
                ])
                ->orderByDesc('scanned_at')
                ->get()
            )
                ->map(fn (object $result): array => $this->mapDatabaseFinding((array) $result))
                ->filter(fn (array $finding): bool => $this->isRemoteBackedCachedFinding($finding))
                ->values()
        );
    }

    protected function isRemoteBackedCachedFinding(array $finding): bool
    {
        $metadata = $finding['metadata'] ?? [];

        foreach ([
            $metadata['remote_task_id'] ?? null,
            $metadata['s3_prefix'] ?? null,
            $metadata['s3_path'] ?? null,
        ] as $candidate) {
            if (is_string($candidate) && filled($candidate)) {
                return true;
            }
        }

        $scanId = $finding['scan_id'] ?? null;

        return is_string($scanId) && Str::isUuid($scanId);
    }

    protected function mapDatabaseFinding(array $result): array
    {
        $metadata = json_decode((string) ($result['metadata'] ?? ''), true);
        $metadata = is_array($metadata) ? $metadata : [];
        $bucket = Str::upper((string) ($metadata['status_bucket'] ?? $result['severity'] ?? 'WARN'));
        $scanStatus = $metadata['scan_status']
            ?? (Str::contains(Str::lower((string) ($result['scan_finding'] ?? '')), 'execution failed') ? 'FAILED' : 'COMPLETED');

        return [
            'tool' => (string) ($result['source_tool'] ?? $metadata['tool'] ?? 'unknown'),
            'scan_id' => (string) ($metadata['remote_task_id'] ?? $metadata['scan_id'] ?? $result['task_identifier'] ?? 'unknown-task'),
            'scan_status' => Str::upper((string) $scanStatus),
            'cluster_name' => (string) ($result['cluster_name'] ?? $metadata['cluster_name'] ?? 'Unknown cluster'),
            'scanned_at' => $this->normalizeScannedAt($result['scanned_at'] ?? null),
            'status_bucket' => $bucket,
            'description' => (string) ($result['scan_finding'] ?? 'Finding generated from imported scan result.'),
            'recommendation' => (string) ($result['recommendation'] ?? 'Review the reported issue and apply the recommended control.'),
            'suggestion' => (string) ($result['suggestion'] ?? 'Review this finding with the security team and remediate as needed.'),
            'object' => (string) ($metadata['object'] ?? $metadata['resource'] ?? $metadata['name'] ?? $result['cluster_name'] ?? 'Finding context'),
            'metadata' => array_merge($metadata, [
                'scan_id' => $metadata['remote_task_id'] ?? $metadata['scan_id'] ?? $result['task_identifier'] ?? null,
                'remote_task_id' => $metadata['remote_task_id'] ?? $metadata['scan_id'] ?? null,
                'local_task_id' => $metadata['local_task_id'] ?? $result['task_identifier'] ?? null,
                'scan_status' => Str::upper((string) $scanStatus),
                'cluster_name' => $metadata['cluster_name'] ?? $result['cluster_name'] ?? null,
                'object' => $metadata['object'] ?? $metadata['resource'] ?? $metadata['name'] ?? $result['cluster_name'] ?? null,
            ]),
        ];
    }

    protected function aggregateFindingsByScanTool(Collection $findings): Collection
    {
        return $findings
            ->groupBy(function (array $finding): string {
                return implode('|', [
                    $finding['scan_id'] ?? 'unknown-task',
                    $finding['tool'] ?? 'unknown-tool',
                    $finding['cluster_name'] ?? 'unknown-cluster',
                ]);
            })
            ->map(function (Collection $group): array {
                $group = $group->sortByDesc(fn (array $finding): int => $this->severityRank((string) ($finding['status_bucket'] ?? 'WARN')))->values();
                $primary = $group->first() ?? [];
                $counts = [
                    'PASS' => $group->where('status_bucket', 'PASS')->count(),
                    'FAIL' => $group->where('status_bucket', 'FAIL')->count(),
                    'WARN' => $group->where('status_bucket', 'WARN')->count(),
                ];
                $statusBucket = $counts['FAIL'] > 0 ? 'FAIL' : ($counts['WARN'] > 0 ? 'WARN' : 'PASS');
                $topFinding = $primary['description'] ?? 'Parsed scan result summary.';
                $summary = collect([
                    $counts['FAIL'] > 0 ? "{$counts['FAIL']} fail" . ($counts['FAIL'] > 1 ? 's' : '') : null,
                    $counts['WARN'] > 0 ? "{$counts['WARN']} warning" . ($counts['WARN'] > 1 ? 's' : '') : null,
                    $counts['PASS'] > 0 ? "{$counts['PASS']} pass" . ($counts['PASS'] > 1 ? 'es' : '') : null,
                ])->filter()->implode(', ');

                return [
                    'tool' => $primary['tool'] ?? 'unknown',
                    'scan_id' => $primary['scan_id'] ?? 'unknown-task',
                    'scan_status' => $primary['scan_status'] ?? 'COMPLETED',
                    'cluster_name' => $primary['cluster_name'] ?? 'Unknown cluster',
                    'scanned_at' => $group
                        ->pluck('scanned_at')
                        ->filter()
                        ->sortByDesc(fn (Carbon $value): int => $value->timestamp)
                        ->first(),
                    'status_bucket' => $statusBucket,
                    'description' => trim(implode(' ', array_filter([
                        $summary !== '' ? 'Summary: ' . $summary . '.' : null,
                        filled($topFinding) ? 'Top finding: ' . Str::limit($topFinding, 240) : null,
                    ]))),
                    'recommendation' => $primary['recommendation'] ?? 'Review the scan result summary and open task findings for detailed remediation.',
                    'suggestion' => $primary['suggestion'] ?? 'Use this summary to identify the tool result that needs deeper review.',
                    'object' => $primary['object'] ?? ($primary['cluster_name'] ?? 'Scan result'),
                    'metadata' => array_merge($primary['metadata'] ?? [], [
                        'finding_counts' => $counts,
                        'object' => $primary['cluster_name'] ?? ($primary['object'] ?? 'Scan result'),
                        'top_finding' => $topFinding,
                    ]),
                ];
            })
            ->sortByDesc(fn (array $finding): array => [
                $this->severityRank((string) ($finding['status_bucket'] ?? 'WARN')),
                $finding['scanned_at'] instanceof Carbon ? $finding['scanned_at']->timestamp : 0,
            ])
            ->values();
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

    protected function transformFinding(array $finding): array
    {
        $metadata = $finding['metadata'] ?? [];
        $bucket = $finding['status_bucket'];
        $scanId = $this->resolveDisplayScanId($finding, $metadata);
        $localTaskId = $this->resolveLocalTaskId($finding, $metadata);

        return [
            'key' => implode('-', array_filter([
                $scanId,
                $finding['tool'] ?? null,
                $finding['cluster_name'] ?? null,
                $metadata['sample_file'] ?? null,
                $metadata['control_id'] ?? null,
                $metadata['test_number'] ?? null,
                $metadata['rule_uuid'] ?? null,
                md5(($finding['description'] ?? '') . ($finding['object'] ?? '')),
            ])),
            'scan_id' => $scanId,
            'task_identifier' => $localTaskId,
            'local_task_id' => $localTaskId,
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

    protected function resolveDisplayScanId(array $finding, array $metadata): string
    {
        foreach ([
            $metadata['remote_task_id'] ?? null,
            $finding['scan_id'] ?? null,
            $metadata['scan_id'] ?? null,
        ] as $candidate) {
            if (is_string($candidate) && filled($candidate)) {
                return $candidate;
            }
        }

        $prefix = $metadata['s3_prefix'] ?? null;

        if (is_string($prefix) && filled($prefix)) {
            $segments = array_values(array_filter(explode('/', trim($prefix, '/'))));

            if (($segments[0] ?? null) === 'result' && filled($segments[1] ?? null)) {
                return (string) $segments[1];
            }
        }

        return 'sample-scan';
    }

    protected function resolveLocalTaskId(array $finding, array $metadata): ?string
    {
        foreach ([
            $metadata['local_task_id'] ?? null,
            $metadata['task_identifier'] ?? null,
        ] as $candidate) {
            if (is_string($candidate) && filled($candidate)) {
                return $candidate;
            }
        }

        return null;
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
