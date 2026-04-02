<?php

namespace App\Services;

use App\Models\SecurityTaskResult;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class DashboardResultService
{
    public function baseQuery(?array $filters = null): Builder
    {
        $filters ??= [];

        return SecurityTaskResult::query()
            ->with('task.clusterAgent')
            ->when(
                filled($filters['task_identifier'] ?? null),
                fn (Builder $query): Builder => $query->where('task_identifier', $filters['task_identifier']),
            )
            ->when(
                filled($filters['source_tool'] ?? null),
                fn (Builder $query): Builder => $query->where('source_tool', $filters['source_tool']),
            )
            ->when(
                filled($filters['cluster_name'] ?? null),
                fn (Builder $query): Builder => $query->whereHas(
                    'task.clusterAgent',
                    fn (Builder $clusterQuery): Builder => $clusterQuery->where('cluster_name', $filters['cluster_name']),
                ),
            );
    }

    public function summarize(?array $filters = null): array
    {
        $summary = [
            'PASS' => 0,
            'FAIL' => 0,
            'WARN' => 0,
        ];

        $this->baseQuery($filters)
            ->get(['severity', 'metadata'])
            ->each(function (SecurityTaskResult $result) use (&$summary): void {
                $bucket = $this->bucketForResult($result);
                $summary[$bucket]++;
            });

        return $summary;
    }

    public function getTopFindings(?array $filters = null, ?string $search = null): Collection
    {
        $records = $this->baseQuery($filters)
            ->orderByDesc('scanned_at')
            ->get()
            ->map(fn (SecurityTaskResult $result): array => $this->transformResult($result))
            ->filter(fn (array $finding): bool => in_array($finding['status'], ['FAIL', 'WARN'], true))
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
                    $finding['task_identifier'] ?? '',
                    $finding['source_tool'] ?? '',
                    $finding['cluster_name'] ?? '',
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

    public function bucketForResult(SecurityTaskResult $result): string
    {
        $severity = Str::upper((string) $result->severity);
        $status = Str::upper((string) ($result->metadata['status'] ?? ''));

        return match (true) {
            in_array($severity, ['FAIL', 'CRITICAL', 'HIGH'], true),
            in_array($status, ['FAIL', 'FAILED'], true) => 'FAIL',
            in_array($severity, ['WARN', 'MEDIUM'], true),
            in_array($status, ['WARN', 'WARNING'], true) => 'WARN',
            default => 'PASS',
        };
    }

    protected function transformResult(SecurityTaskResult $result): array
    {
        $metadata = $result->metadata ?? [];
        $bucket = $this->bucketForResult($result);

        return [
            'key' => (string) $result->id,
            'task_identifier' => $result->task_identifier,
            'source_tool' => $result->source_tool,
            'cluster_name' => $result->task?->clusterAgent?->cluster_name,
            'control_id' => $metadata['control_id'] ?? null,
            'test_number' => $metadata['test_number'] ?? null,
            'section' => $metadata['section'] ?? null,
            'scan_finding' => $result->scan_finding,
            'recommendation' => $result->recommendation,
            'suggestion' => $result->suggestion,
            'severity' => $result->severity,
            'status' => $bucket,
            'severity_rank' => match ($bucket) {
                'FAIL' => 3,
                'WARN' => 2,
                default => 1,
            },
            'actual' => $metadata['actual'] ?? null,
            'expected' => $metadata['expected'] ?? null,
            'object_label' => $this->resolveObjectLabel($metadata),
            'scanned_at' => optional($result->scanned_at)?->timestamp ?? 0,
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
        ])->filter()->join(' | ') ?: 'Finding context';
    }
}
