<?php

namespace App\Services;

use App\Models\SecurityTask;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
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

        return $this->limitS3Files($files);
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

    public function getS3ResultFilesForTool(string $prefix, string $tool): Collection
    {
        $disk = env('SCAN_S3_DISK', 's3');
        $normalizedTool = $this->normalizeToolName($tool);

        if (blank($normalizedTool)) {
            return collect();
        }

        $paths = $this->candidateS3ResultPaths($prefix, $normalizedTool);

        return collect([[
            'tool' => $normalizedTool,
            'path' => $paths[0],
            'filename' => basename($paths[0]),
            'disk' => $disk,
            'last_modified' => 0,
            'fallback_paths' => array_slice($paths, 1),
            'prefix' => rtrim($prefix, '/'),
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

                $paths = $this->candidateS3ResultPaths($resultPrefix, $tool);

                return [
                    'tool' => $tool,
                    'path' => $paths[0],
                    'filename' => basename($paths[0]),
                    'disk' => $disk,
                    'last_modified' => (int) ($dispatch['completed_at'] ?? 0),
                    'fallback_paths' => array_slice($paths, 1),
                    'prefix' => $resultPrefix,
                ];
            })
            ->filter()
            ->values();
    }

    protected function getRecentResultPrefixesByTool(Collection $requestedTools): Collection
    {
        $maxTasks = max(10, (int) env('SCAN_S3_TASK_LOOKBACK', 50));

        return collect(
            DB::table('security_tasks')
                ->select(['id', 'summary', 'completed_at', 'updated_at'])
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
                    ->filter(fn (mixed $dispatch): bool => is_array($dispatch))
                    ->map(function (array $dispatch) use ($task): array {
                        return [
                            'tool' => $this->normalizeToolName((string) ($dispatch['tool'] ?? '')),
                            'result_prefix' => (string) ($dispatch['result_prefix'] ?? ''),
                            'completed_at' => $this->normalizeTimestamp($task->completed_at ?? null)
                                ?? $this->normalizeTimestamp($task->updated_at ?? null)
                                ?? 0,
                            'task_id' => $task->id,
                        ];
                    });
            })
            ->filter(function (array $dispatch) use ($requestedTools): bool {
                return filled($dispatch['tool'])
                    && filled($dispatch['result_prefix'])
                    && $requestedTools->contains($dispatch['tool']);
            })
            ->sortByDesc(fn (array $dispatch): int => (int) ($dispatch['completed_at'] ?? 0))
            ->unique('tool')
            ->values();
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

    public function parseFile(array $file): Collection
    {
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

                if (! Str::contains($exception->getMessage(), 'Unable to read file from location')) {
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
                return $this->parseSampleFile($discoveredPath, $tool, $disk);
            }
        }

        if ($lastException) {
            throw $lastException;
        }

        return collect();
    }

    protected function candidateS3ResultPaths(string $prefix, string $tool): array
    {
        $prefix = rtrim($prefix, '/');
        $tool = $this->normalizeToolName($tool) ?? $tool;

        $candidates = match ($tool) {
            'kubebench' => ['result-kubebench.json', 'result-kube-bench.json', 'result.json'],
            'kubescape' => ['result-kubescape.json', 'result-kube-escape.json', 'result.json'],
            'checkov' => ['result-checkov.json', 'result.json'],
            'nmap' => ['result-nmap.json', 'result.json'],
            'rbac-tool' => ['result-rbac-tool.json', 'result-rbac_tool.json', 'result-rbac.json', 'result.json'],
            default => ['result-' . $tool . '.json', 'result.json'],
        };

        return array_map(
            fn (string $filename): string => $prefix . '/' . $filename,
            array_values(array_unique($candidates)),
        );
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

    public function getNormalizedFindingsForTools(array $tools): Collection
    {
        $files = $this->getAvailableSampleFiles($tools);

        if ($files->isEmpty()) {
            throw new RuntimeException('No matching scan sample files were found for the selected tools.');
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
