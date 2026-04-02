<?php

namespace App\Services;

use App\Enums\SecurityTaskStatus;
use App\Models\SecurityTask;
use App\Models\SecurityTaskResult;
use Illuminate\Support\Carbon;
use Throwable;

class TaskExecutionService
{
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

    public function __construct(
        protected ScanService $scanService,
    ) {}

    public function run(SecurityTask $task): void
    {
        $task->results()->delete();
        $selectedTools = collect($task->tools ?? [])
            ->filter(fn (?string $tool): bool => array_key_exists((string) $tool, self::getAvailableTools()))
            ->values()
            ->all();

        $task->update([
            'status' => SecurityTaskStatus::Running,
            'progress' => 10,
            'started_at' => now(),
            'completed_at' => null,
            'last_message' => 'Loading sample scan files for the selected security tools.',
        ]);

        try {
            $findings = $this->scanService->getNormalizedFindingsForTools($selectedTools);

            $task->update([
                'progress' => 55,
                'last_message' => 'Normalizing sample findings from each selected tool and building task result rows.',
            ]);

            foreach ($findings as $finding) {
                SecurityTaskResult::create([
                    'security_task_id' => $task->id,
                    'task_identifier' => $task->task_id,
                    'source_tool' => $finding['tool'],
                    'cluster_name' => $finding['cluster_name'] ?? null,
                    'severity' => $finding['status_bucket'],
                    'scan_finding' => $this->formatFinding($finding),
                    'recommendation' => $finding['recommendation'] ?? 'Review the reported issue and apply the recommended hardening control.',
                    'suggestion' => $this->makeSuggestion($finding),
                    'metadata' => $finding['metadata'] ?? [],
                    'scanned_at' => $finding['scanned_at'] ?? Carbon::now(),
                ]);
            }

            $summary = $this->scanService->summarize($findings);
            $actionableCount = $findings
                ->filter(fn (array $finding): bool => in_array($finding['status_bucket'] ?? null, ['FAIL', 'WARN'], true))
                ->count();

            $task->update([
                'status' => SecurityTaskStatus::Completed,
                'progress' => 100,
                'completed_at' => now(),
                'summary' => $summary,
                'last_message' => sprintf(
                    'Completed with %d actionable findings from %d normalized checks across %d selected tool(s).',
                    $actionableCount,
                    $findings->count(),
                    count($selectedTools),
                ),
            ]);
        } catch (Throwable $exception) {
            report($exception);

            $task->update([
                'status' => SecurityTaskStatus::Failed,
                'progress' => 0,
                'completed_at' => now(),
                'last_message' => $exception->getMessage(),
            ]);
        }
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
}
