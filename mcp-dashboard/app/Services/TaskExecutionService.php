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
            'kubebench' => 'Kube Bench',
            'kubescape' => 'Kubescape',
            'rbac-tool' => 'RBAC Tool',
            'nmap' => 'Nmap',
            'trivy' => 'Trivy',
            'kube-hunter' => 'Kube Hunter',
        ];
    }

    public function __construct(
        protected ScanService $scanService,
    ) {}

    public function run(SecurityTask $task): void
    {
        $task->results()->delete();

        $task->update([
            'status' => SecurityTaskStatus::Running,
            'progress' => 15,
            'started_at' => now(),
            'completed_at' => null,
            'last_message' => 'Loading security scan data from source JSON.',
        ]);

        try {
            $scanData = $this->scanService->getScanData();
            $findings = collect($this->scanService->extractFindings($scanData));

            $task->update([
                'progress' => 55,
                'last_message' => 'Normalizing findings and building task result rows.',
            ]);

            $results = $findings
                ->filter(fn (array $finding): bool => in_array($finding['status'] ?? null, ['FAIL', 'WARN'], true))
                ->values();

            $scannedAt = Carbon::now();
            $sourceTool = $task->tools[0] ?? 'multi-tool';

            foreach ($results as $finding) {
                SecurityTaskResult::create([
                    'security_task_id' => $task->id,
                    'task_identifier' => $task->task_id,
                    'source_tool' => $sourceTool,
                    'severity' => $finding['status'],
                    'scan_finding' => $this->formatFinding($finding),
                    'recommendation' => $finding['remediation'] ?? 'Review the reported issue and apply the recommended hardening control.',
                    'suggestion' => $this->makeSuggestion($finding),
                    'metadata' => $finding,
                    'scanned_at' => $scannedAt,
                ]);
            }

            $summary = $this->scanService->summarize($findings->all());

            $task->update([
                'status' => SecurityTaskStatus::Completed,
                'progress' => 100,
                'completed_at' => now(),
                'summary' => $summary,
                'last_message' => sprintf(
                    'Completed with %d actionable findings from %d total checks.',
                    $results->count(),
                    $findings->count(),
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
        $actual = trim((string) ($finding['actual'] ?? ''));

        if (filled($actual)) {
            $findingText .= ' Actual value: ' . $actual;
        }

        return $findingText;
    }

    protected function makeSuggestion(array $finding): string
    {
        return match ($finding['status'] ?? null) {
            'FAIL' => 'Treat this as a priority issue, remediate the control, then rerun the task to validate the fix.',
            'WARN' => 'Review the configuration with the platform owner and confirm whether the warning is acceptable or needs remediation.',
            default => 'No additional action is required.',
        };
    }
}
