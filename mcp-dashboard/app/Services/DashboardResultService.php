<?php

namespace App\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class DashboardResultService
{
    protected const CACHE_VERSION = '2026-04-07-findings-scalar-v1';

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
        $tools = array_keys(TaskExecutionService::getAvailableTools());
        $ttl = max(1, (int) env('SCAN_CACHE_TTL_SECONDS', 300));
        $cacheKey = 'dashboard.scan-findings.' . md5(json_encode([
            'version' => self::CACHE_VERSION,
            'source' => env('SCAN_SOURCE', 'local'),
            'disk' => env('SCAN_S3_DISK', 's3'),
            'prefix' => env('SCAN_S3_PREFIX', 'result'),
            'tools' => $tools,
            'max_files' => env('SCAN_S3_MAX_FILES', 200),
        ]));
        $cached = Cache::get($cacheKey);

        if (is_array($cached) && $cached !== []) {
            return collect($cached)->map(fn (array $finding): array => $this->hydrateFinding($finding))->values();
        }

        $fresh = $this->scanService->getNormalizedFindingsForTools($tools)->values();
        $serialized = $fresh
            ->map(fn (array $finding): array => $this->serializeFinding($finding))
            ->values();

        if ($fresh->isNotEmpty()) {
            Cache::put($cacheKey, $serialized->all(), now()->addSeconds($ttl));
        } elseif (! is_array($cached)) {
            Cache::put($cacheKey, [], now()->addSeconds(min($ttl, 60)));
        }

        return $serialized->map(fn (array $finding): array => $this->hydrateFinding($finding))->values();
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

        if (is_string($value) && filled($value)) {
            return Carbon::parse($value);
        }

        return null;
    }
}
