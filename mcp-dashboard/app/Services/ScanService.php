<?php

namespace App\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use RuntimeException;

class ScanService
{
    public function getAvailableSampleFiles(?array $tools = null): Collection
    {
        $directory = storage_path('app/scan');
        $requestedTools = collect($tools ?? [])->filter()->values();

        if (! File::isDirectory($directory)) {
            throw new RuntimeException('Scan sample directory was not found.');
        }

        return collect(File::files($directory))
            ->filter(fn ($file): bool => Str::endsWith($file->getFilename(), '.json'))
            ->map(function ($file): array {
                $tool = $this->detectToolFromFilename($file->getFilename());

                return [
                    'tool' => $tool,
                    'path' => $file->getPathname(),
                    'filename' => $file->getFilename(),
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

    public function getNormalizedFindingsForTools(array $tools): Collection
    {
        $files = $this->getAvailableSampleFiles($tools);

        if ($files->isEmpty()) {
            throw new RuntimeException('No matching scan sample files were found for the selected tools.');
        }

        return $files
            ->flatMap(fn (array $file): Collection => $this->parseSampleFile($file['path'], $file['tool']))
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

    protected function parseSampleFile(string $path, ?string $tool = null): Collection
    {
        if (! File::exists($path)) {
            throw new RuntimeException("Scan sample file does not exist: {$path}");
        }

        $payload = json_decode(File::get($path), true);

        if (! is_array($payload)) {
            throw new RuntimeException("Scan sample file is not valid JSON: {$path}");
        }

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
                                        'raw' => $result,
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
                                'raw' => $control,
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
                                'raw' => $check,
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
                        'raw' => $entry,
                    ],
                    suggestion: $this->makeSuggestion($bucket, 'rbac-tool'),
                );
            })
            ->values();
    }

    protected function parseNmap(array $context): Collection
    {
        return collect($context['payload']['stdout'] ?? [])
            ->flatMap(function (array $scanEntry, string $scanKey) use ($context): array {
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
                                'raw' => $port,
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

        return match (true) {
            Str::startsWith($lower, 'kubebench-') => 'kubebench',
            Str::startsWith($lower, 'kubescape-') => 'kubescape',
            Str::startsWith($lower, 'checkov-') => 'checkov',
            Str::startsWith($lower, 'nmap') => 'nmap',
            Str::startsWith($lower, 'rbac-') => 'rbac-tool',
            default => null,
        };
    }

    protected function detectToolFromPayload(array $payload): ?string
    {
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
}
