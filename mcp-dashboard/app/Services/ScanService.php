<?php

namespace App\Services;

use Aws\S3\S3Client;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use RuntimeException;

class ScanService
{
    public function getAvailableSampleFiles(?array $tools = null): Collection
    {
        $requestedTools = collect($tools)->filter()->values()->all();
        $files = match ($this->getScanSource()) {
            's3' => $this->getS3SampleFiles($requestedTools),
            default => $this->getLocalSampleFiles(),
        };

        return $files
            ->sortBy(['tool', 'filename'])
            ->values();
    }

    public function getNormalizedFindingsForTools(array $tools): Collection
    {
        $requestedTools = collect($tools)->filter()->values();
        $files = $this->getAvailableSampleFiles($tools);

        if ($files->isEmpty()) {
            throw new RuntimeException('No matching scan sample files were found for the selected tools.');
        }

        $findings = $files
            ->flatMap(function (array $file): Collection {
                try {
                    return $this->parseSampleFile($file);
                } catch (RuntimeException $exception) {
                    if (
                        Str::contains($exception->getMessage(), 'Unable to detect tool type for scan sample') ||
                        Str::contains($exception->getMessage(), 'Scan sample file is not valid JSON') ||
                        Str::contains($exception->getMessage(), 'Scan sample file is empty')
                    ) {
                        Log::warning('Skipping scan sample during dashboard ingestion.', [
                            'path' => $file['path'] ?? null,
                            'filename' => $file['filename'] ?? null,
                            'source' => $file['source'] ?? null,
                            'reason' => $exception->getMessage(),
                        ]);

                        return collect();
                    }

                    throw $exception;
                }
            })
            ->values();

        if ($requestedTools->isEmpty()) {
            return $findings;
        }

        return $findings
            ->filter(fn (array $finding): bool => $requestedTools->contains($finding['tool'] ?? null))
            ->values();
    }

    public function parseFile(array $file): Collection
    {
        return $this->parseSampleFile($file);
    }

    public function getS3ResultFiles(string $prefix, ?string $disk = null): Collection
    {
        $resolvedDisk = $disk ?: $this->getS3Disk();
        $normalizedPrefix = trim($prefix, '/');

        if ($normalizedPrefix === '') {
            return collect();
        }

        return collect(Storage::disk($resolvedDisk)->allFiles($normalizedPrefix))
            ->filter(fn (string $path): bool => Str::endsWith(Str::lower($path), '.json'))
            ->map(function (string $path) use ($resolvedDisk): array {
                $filename = basename($path);

                return [
                    'source' => 's3',
                    'disk' => $resolvedDisk,
                    'tool' => $this->detectToolFromFilename($filename),
                    'path' => $path,
                    'filename' => $filename,
                ];
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

    protected function parseSampleFile(array $file): Collection
    {
        $contents = $this->readSampleFileContents($file);

        if (trim($contents) === '') {
            throw new RuntimeException("Scan sample file is empty: {$file['path']}");
        }

        $payload = $this->decodeSamplePayload($contents);

        if (! is_array($payload)) {
            throw new RuntimeException("Scan sample file is not valid JSON: {$file['path']}");
        }

        $payload = $this->normalizePayload($payload);

        $tool = $file['tool'] ?? $this->detectToolFromFilename($file['filename']) ?? $this->detectToolFromPayload($payload);

        if (blank($tool)) {
            throw new RuntimeException("Unable to detect tool type for scan sample: {$file['path']}");
        }

        $context = [
            'tool' => $tool,
            'filename' => $file['filename'],
            'path' => $file['path'],
            'source' => $file['source'] ?? 'local',
            'scan_id' => $this->resolveScanId($payload, $file['filename']),
            'scan_status' => $this->resolveScanStatus($payload),
            'cluster_name' => $payload['cluster_name'] ?? ($payload['stdout']['clusterName'] ?? 'Unknown cluster'),
            'scanned_at' => $this->resolveScannedAt($payload),
            'payload' => $payload,
        ];

        $findings = match ($tool) {
            'kubebench' => $this->parseKubebench($context),
            'kubescape' => $this->parseKubescape($context),
            'checkov' => $this->parseCheckov($context),
            'nmap' => $this->parseNmap($context),
            'rbac-tool' => $this->parseRbacTool($context),
            default => throw new RuntimeException("Tool '{$tool}' is not supported by the sample parser."),
        };

        $logContext = [
            'tool' => $tool,
            'path' => $context['path'],
            'source' => $context['source'],
            'scan_id' => $context['scan_id'],
            'cluster_name' => $context['cluster_name'],
            'findings_count' => $findings->count(),
        ];

        if ($findings->isEmpty()) {
            Log::warning('Scan sample produced zero findings during dashboard ingestion.', $logContext + [
                'top_level_keys' => array_keys($payload),
                'stdout_keys' => array_keys(is_array($payload['stdout'] ?? null) ? $payload['stdout'] : []),
                'stdout_type' => gettype($payload['stdout'] ?? null),
                'stdout_length' => is_string($payload['stdout'] ?? null) ? strlen($payload['stdout']) : null,
                'stdout_preview' => is_string($payload['stdout'] ?? null)
                    ? Str::limit(preg_replace('/\s+/', ' ', $payload['stdout']), 240)
                    : null,
            ]);
        } else {
            Log::info('Scan sample parsed successfully for dashboard ingestion.', $logContext);
        }

        return $findings;
    }

    protected function getLocalSampleFiles(): Collection
    {
        $directory = storage_path(env('SCAN_LOCAL_PATH', 'app/scan'));

        if (! File::isDirectory($directory)) {
            throw new RuntimeException("Local scan sample directory was not found: {$directory}");
        }

        return collect(File::files($directory))
            ->filter(fn ($file): bool => Str::endsWith($file->getFilename(), '.json'))
            ->map(function ($file): array {
                $filename = $file->getFilename();

                return [
                    'source' => 'local',
                    'tool' => $this->detectToolFromFilename($filename),
                    'path' => $file->getPathname(),
                    'filename' => $filename,
                ];
            })
            ->values();
    }

    protected function getS3SampleFiles(array $requestedTools = []): Collection
    {
        $disk = $this->getS3Disk();
        $prefix = trim((string) env('SCAN_S3_PREFIX', 'result'), '/');
        $maxFiles = max(1, (int) env('SCAN_S3_MAX_FILES', 200));
        $perToolLimit = max(1, (int) env('SCAN_S3_MAX_FILES_PER_TOOL', 1));
        $cacheTtl = max(1, (int) env('SCAN_S3_INDEX_CACHE_TTL_SECONDS', 300));
        $cacheKey = 'scan-service.s3-index.' . md5(json_encode([
            'version' => '2026-04-06-s3-list-v2',
            'disk' => $disk,
            'prefix' => $prefix,
            'max_files' => $maxFiles,
            'per_tool_limit' => $perToolLimit,
            'requested_tools' => $requestedTools,
        ]));
        $paths = Cache::remember(
            $cacheKey,
            now()->addSeconds($cacheTtl),
            fn (): array => $this->listS3SamplePaths($disk, $prefix, $maxFiles, $perToolLimit, $requestedTools),
        );

        return collect($paths)
            ->map(function (string $path) use ($disk): array {
                $filename = basename($path);

                return [
                    'source' => 's3',
                    'disk' => $disk,
                    'tool' => $this->detectToolFromFilename($filename),
                    'path' => $path,
                    'filename' => $filename,
                ];
            })
            ->values();
    }

    protected function readSampleFileContents(array $file): string
    {
        return match ($file['source'] ?? 'local') {
            's3' => $this->readS3SampleFileContents(
                disk: $file['disk'] ?? $this->getS3Disk(),
                path: $file['path'],
            ),
            default => $this->readLocalSampleFileContents($file['path']),
        };
    }

    protected function readLocalSampleFileContents(string $path): string
    {
        if (! File::exists($path)) {
            throw new RuntimeException("Local scan sample file does not exist: {$path}");
        }

        return (string) File::get($path);
    }

    protected function readS3SampleFileContents(string $disk, string $path): string
    {
        $stream = Storage::disk($disk)->readStream($path);

        if (! is_resource($stream)) {
            throw new RuntimeException("Unable to open S3 stream for scan sample: {$path}");
        }

        $contents = '';

        try {
            while (! feof($stream)) {
                $chunk = fread($stream, 1024 * 1024);

                if ($chunk === false) {
                    throw new RuntimeException("Unable to read S3 stream for scan sample: {$path}");
                }

                $contents .= $chunk;
            }
        } finally {
            fclose($stream);
        }

        return $contents;
    }

    protected function getScanSource(): string
    {
        return Str::lower((string) env('SCAN_SOURCE', 'local'));
    }

    protected function getS3Disk(): string
    {
        return (string) env('SCAN_S3_DISK', 's3');
    }

    protected function listS3SamplePaths(string $disk, string $prefix, int $maxFiles, int $perToolLimit, array $requestedTools = []): array
    {
        $bucket = (string) config("filesystems.disks.{$disk}.bucket");

        if (blank($bucket)) {
            throw new RuntimeException("S3 bucket is not configured for disk [{$disk}].");
        }

        $client = $this->makeS3Client($disk);
        $normalizedPrefix = $prefix === '' ? '' : $prefix . '/';
        $pageSize = max(10, min(250, (int) env('SCAN_S3_PAGE_SIZE', 100)));
        $allowedTools = collect($requestedTools)
            ->filter(fn ($tool): bool => is_string($tool) && filled($tool))
            ->map(fn (string $tool): string => Str::lower($tool))
            ->values();
        $supportedToolCount = max(
            1,
            $allowedTools->isNotEmpty()
                ? $allowedTools->unique()->count()
                : count(array_keys(TaskExecutionService::getAvailableTools())),
        );
        $targetCount = min($maxFiles, $supportedToolCount * $perToolLimit);
        $paths = [];
        $countsByTool = [];
        $continuationToken = null;

        do {
            $params = [
                'Bucket' => $bucket,
                'Prefix' => $normalizedPrefix,
                'MaxKeys' => $pageSize,
            ];

            if (filled($continuationToken)) {
                $params['ContinuationToken'] = $continuationToken;
            }

            $result = $client->listObjectsV2($params);

            foreach (($result['Contents'] ?? []) as $object) {
                $key = (string) ($object['Key'] ?? '');

                if (! Str::endsWith(Str::lower($key), '.json')) {
                    continue;
                }

                $tool = $this->detectToolFromFilename(basename($key));

                if (blank($tool)) {
                    continue;
                }

                if ($allowedTools->isNotEmpty() && ! $allowedTools->contains(Str::lower($tool))) {
                    continue;
                }

                if (($countsByTool[$tool] ?? 0) >= $perToolLimit) {
                    continue;
                }

                $paths[] = $key;
                $countsByTool[$tool] = ($countsByTool[$tool] ?? 0) + 1;

                if (count($paths) >= $targetCount) {
                    break 2;
                }
            }

            $continuationToken = $result['NextContinuationToken'] ?? null;
        } while (($result['IsTruncated'] ?? false) && filled($continuationToken));

        return $paths;
    }

    protected function makeS3Client(string $disk): S3Client
    {
        $config = config("filesystems.disks.{$disk}");

        if (! is_array($config)) {
            throw new RuntimeException("Filesystem disk [{$disk}] is not configured.");
        }

        $clientConfig = [
            'version' => 'latest',
            'region' => $config['region'] ?? env('AWS_DEFAULT_REGION'),
            'use_path_style_endpoint' => (bool) ($config['use_path_style_endpoint'] ?? false),
        ];

        if (filled($config['endpoint'] ?? null)) {
            $clientConfig['endpoint'] = $config['endpoint'];
        }

        return new S3Client($clientConfig);
    }

    protected function decodeSamplePayload(string $contents): ?array
    {
        $trimmed = trim(preg_replace('/^\xEF\xBB\xBF/', '', $contents) ?? $contents);

        foreach ($this->yieldCandidateJsonStrings($trimmed) as $candidate) {
            $decoded = json_decode($candidate, true);

            if (is_array($decoded)) {
                return $decoded;
            }

            if (is_string($decoded)) {
                $decodedString = json_decode($decoded, true);

                if (is_array($decodedString)) {
                    return $decodedString;
                }
            }

            foreach ($this->yieldEscapedJsonCandidates($candidate) as $escapedCandidate) {
                $decodedEscaped = json_decode($escapedCandidate, true);

                if (is_array($decodedEscaped)) {
                    return $decodedEscaped;
                }
            }

            $pseudoJson = $this->normalizePseudoJsonString($candidate);

            if ($pseudoJson !== null) {
                $decodedPseudoJson = json_decode($pseudoJson, true);

                if (is_array($decodedPseudoJson)) {
                    return $decodedPseudoJson;
                }
            }

            $pythonLiteral = $this->parsePythonLiteralPayload($candidate);

            if (is_array($pythonLiteral)) {
                return $pythonLiteral;
            }
        }

        return null;
    }

    protected function yieldCandidateJsonStrings(string $contents): \Generator
    {
        if ($contents === '') {
            return;
        }

        yield $contents;

        if (strlen($contents) > 1024 * 1024) {
            return;
        }

        $firstChar = $contents[0];

        if (in_array($firstChar, ['{', '[', '"'], true)) {
            return;
        }

        $firstBrace = strpos($contents, '{');
        $lastBrace = strrpos($contents, '}');

        if ($firstBrace !== false && $lastBrace !== false && $lastBrace > $firstBrace) {
            yield substr($contents, $firstBrace, $lastBrace - $firstBrace + 1);
        }

        $firstBracket = strpos($contents, '[');
        $lastBracket = strrpos($contents, ']');

        if (
            $firstBracket !== false &&
            $lastBracket !== false &&
            $lastBracket > $firstBracket &&
            ($firstBrace === false || $firstBracket < $firstBrace)
        ) {
            yield substr($contents, $firstBracket, $lastBracket - $firstBracket + 1);
        }
    }

    protected function normalizePayload(array $payload): array
    {
        foreach (['stdout', 'payload', 'data', 'result', 'body', 'partial_results', 'stderr'] as $key) {
            $value = $payload[$key] ?? null;

            if (
                is_string($value) &&
                filled(trim($value)) &&
                $this->looksLikeEncodedJson($value)
            ) {
                $decoded = $this->decodeSamplePayload($value);

                if (is_array($decoded)) {
                    $payload[$key] = $decoded;
                }
            }
        }

        if (
            (
                ! isset($payload['stdout']) ||
                (is_string($payload['stdout']) && blank(trim($payload['stdout']))) ||
                $payload['stdout'] === []
            ) &&
            is_string($payload['partial_results'] ?? null) &&
            filled(trim($payload['partial_results']))
        ) {
            $decodedPartialResults = $this->decodeCheckovPayloadString($payload['partial_results']);

            if (is_array($decodedPartialResults)) {
                $payload['stdout'] = $decodedPartialResults;
            }
        }

        if (
            (
                ! isset($payload['stdout']) ||
                (is_string($payload['stdout']) && blank(trim($payload['stdout']))) ||
                $payload['stdout'] === []
            ) &&
            is_string($payload['stderr'] ?? null) &&
            filled(trim($payload['stderr']))
        ) {
            $decodedStderr = $this->decodeCheckovPayloadString($payload['stderr']);

            if (is_array($decodedStderr)) {
                $payload['stdout'] = $decodedStderr;
            }
        }

        if (! isset($payload['stdout']) || ! is_array($payload['stdout'])) {
            if ($this->looksLikeToolPayload($payload)) {
                $payload = ['stdout' => $payload] + $payload;
            } else {
                foreach (['payload', 'data', 'result', 'body', 'partial_results', 'stderr'] as $key) {
                    if (isset($payload[$key]) && is_array($payload[$key]) && $this->looksLikeToolPayload($payload[$key])) {
                        $payload['stdout'] = $payload[$key];
                        break;
                    }
                }
            }
        }

        return $payload;
    }

    protected function looksLikeToolPayload(array $payload): bool
    {
        return
            isset($payload['Controls']) ||
            isset($payload['Totals']) ||
            isset($payload['summaryDetails']) ||
            isset($payload['results']) ||
            isset($payload['Findings']) ||
            isset($payload['nmaprun']) ||
            isset($payload['check_type']);
    }

    protected function looksLikeEncodedJson(string $value): bool
    {
        $trimmed = ltrim($value);

        return in_array($trimmed[0] ?? '', ['{', '[', '"'], true)
            || Str::contains($trimmed, ['{\\"', '[\\"', '\\"Controls\\"', '\\"results\\"', '\\"Findings\\"']);
    }

    protected function yieldEscapedJsonCandidates(string $candidate): \Generator
    {
        if (! Str::contains($candidate, ['\\"', '\\n', '\\r', '\\t'])) {
            return;
        }

        $stripped = stripslashes($candidate);

        if ($stripped !== $candidate && $stripped !== '') {
            yield $stripped;
        }
    }

    protected function normalizePseudoJsonString(string $candidate): ?string
    {
        $trimmed = trim($candidate);

        if (! Str::startsWith($trimmed, ['{', '[']) || ! Str::contains($trimmed, "':")) {
            return null;
        }

        $result = '';
        $token = '';
        $inSingleQuotedString = false;
        $length = strlen($trimmed);

        $flushToken = function () use (&$token, &$result): void {
            if ($token === '') {
                return;
            }

            $result .= match ($token) {
                'None' => 'null',
                'True' => 'true',
                'False' => 'false',
                default => $token,
            };

            $token = '';
        };

        for ($index = 0; $index < $length; $index++) {
            $char = $trimmed[$index];

            if ($inSingleQuotedString) {
                if ($char === '\\' && $index + 1 < $length) {
                    $next = $trimmed[$index + 1];
                    $result .= match ($next) {
                        '\\' => '\\\\',
                        '\'' => '\'',
                        '"' => '\\"',
                        'n' => '\\n',
                        'r' => '\\r',
                        't' => '\\t',
                        default => '\\\\' . $next,
                    };
                    $index++;

                    continue;
                }

                if ($char === '\'') {
                    $result .= '"';
                    $inSingleQuotedString = false;

                    continue;
                }

                $result .= match ($char) {
                    '"' => '\\"',
                    "\n" => '\\n',
                    "\r" => '\\r',
                    "\t" => '\\t',
                    default => $char,
                };

                continue;
            }

            if ($char === '\'') {
                $flushToken();
                $result .= '"';
                $inSingleQuotedString = true;

                continue;
            }

            if (ctype_alpha($char)) {
                $token .= $char;

                continue;
            }

            $flushToken();
            $result .= $char;
        }

        $flushToken();

        return $inSingleQuotedString ? null : $result;
    }

    protected function parsePythonLiteralPayload(string $candidate): ?array
    {
        $trimmed = trim($candidate);

        if (! Str::startsWith($trimmed, ['{', '['])) {
            return null;
        }

        $index = 0;
        $value = $this->parsePythonLiteralValue($trimmed, $index);

        if (! is_array($value)) {
            return null;
        }

        $this->skipPythonLiteralWhitespace($trimmed, $index);

        return $index === strlen($trimmed) ? $value : null;
    }

    protected function parsePythonLiteralValue(string $input, int &$index): mixed
    {
        $this->skipPythonLiteralWhitespace($input, $index);

        if ($index >= strlen($input)) {
            return null;
        }

        return match ($input[$index]) {
            '{' => $this->parsePythonLiteralObject($input, $index),
            '[' => $this->parsePythonLiteralArray($input, $index),
            '\'', '"' => $this->parsePythonLiteralString($input, $index),
            default => $this->parsePythonLiteralScalar($input, $index),
        };
    }

    protected function parsePythonLiteralObject(string $input, int &$index): ?array
    {
        $object = [];
        $index++;

        while (true) {
            $this->skipPythonLiteralWhitespace($input, $index);

            if (($input[$index] ?? null) === '}') {
                $index++;

                return $object;
            }

            $key = $this->parsePythonLiteralValue($input, $index);

            if (! is_string($key)) {
                return null;
            }

            $this->skipPythonLiteralWhitespace($input, $index);

            if (($input[$index] ?? null) !== ':') {
                return null;
            }

            $index++;
            $value = $this->parsePythonLiteralValue($input, $index);
            $object[$key] = $value;

            $this->skipPythonLiteralWhitespace($input, $index);
            $char = $input[$index] ?? null;

            if ($char === ',') {
                $index++;

                continue;
            }

            if ($char === '}') {
                $index++;

                return $object;
            }

            return null;
        }
    }

    protected function parsePythonLiteralArray(string $input, int &$index): ?array
    {
        $array = [];
        $index++;

        while (true) {
            $this->skipPythonLiteralWhitespace($input, $index);

            if (($input[$index] ?? null) === ']') {
                $index++;

                return $array;
            }

            $array[] = $this->parsePythonLiteralValue($input, $index);
            $this->skipPythonLiteralWhitespace($input, $index);
            $char = $input[$index] ?? null;

            if ($char === ',') {
                $index++;

                continue;
            }

            if ($char === ']') {
                $index++;

                return $array;
            }

            return null;
        }
    }

    protected function parsePythonLiteralString(string $input, int &$index): ?string
    {
        $quote = $input[$index] ?? null;

        if (! in_array($quote, ['\'', '"'], true)) {
            return null;
        }

        $index++;
        $result = '';
        $length = strlen($input);

        while ($index < $length) {
            $char = $input[$index];

            if ($char === '\\' && $index + 1 < $length) {
                $next = $input[$index + 1];
                $result .= match ($next) {
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    '\\' => '\\',
                    '\'' => '\'',
                    '"' => '"',
                    default => $next,
                };
                $index += 2;

                continue;
            }

            if ($char === $quote) {
                $index++;

                return $result;
            }

            $result .= $char;
            $index++;
        }

        return null;
    }

    protected function parsePythonLiteralScalar(string $input, int &$index): mixed
    {
        $length = strlen($input);
        $start = $index;

        while ($index < $length && ! in_array($input[$index], [',', '}', ']', ' ', "\n", "\r", "\t"], true)) {
            $index++;
        }

        $token = substr($input, $start, $index - $start);

        return match ($token) {
            'True' => true,
            'False' => false,
            'None' => null,
            default => is_numeric($token) ? ($token + 0) : $token,
        };
    }

    protected function skipPythonLiteralWhitespace(string $input, int &$index): void
    {
        $length = strlen($input);

        while ($index < $length && in_array($input[$index], [' ', "\n", "\r", "\t"], true)) {
            $index++;
        }
    }

    protected function matchesSupportedScanFilename(string $filename): bool
    {
        return filled($this->detectToolFromFilename($filename));
    }

    protected function parseKubebench(array $context): Collection
    {
        $stdout = $context['payload']['stdout'] ?? [];

        if (is_string($stdout) && filled(trim($stdout))) {
            $decodedStdout = $this->decodeToolPayloadString($stdout);

            if (is_array($decodedStdout)) {
                $stdout = $decodedStdout;
            }
        }

        $controls = $stdout['Controls'] ?? $stdout['controls'] ?? $context['payload']['Controls'] ?? [];

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
        $stdout = $this->resolveCheckovStdoutPayload($context['payload']);

        if (is_string($stdout) && filled(trim($stdout))) {
            return collect([
                $this->makeFinding(
                    context: $context,
                    statusBucket: 'FAIL',
                    description: $this->summarizeCheckovExecutionOutput($stdout),
                    recommendation: $this->buildCheckovExecutionRecommendation($stdout),
                    object: $context['cluster_name'] ?: 'Checkov scan execution',
                    metadata: [
                        'tool' => 'checkov',
                        'status' => 'EXECUTION_ERROR',
                        'section' => 'execution',
                        'resource' => $context['cluster_name'] ?: 'Checkov scan execution',
                        'object' => $context['cluster_name'] ?: 'Checkov scan execution',
                        'raw_output_excerpt' => Str::limit(preg_replace('/\s+/', ' ', $stdout), 1000),
                    ],
                    suggestion: 'Fix the Checkov scanner execution issue, rerun the scan, and review the findings again.',
                ),
            ]);
        }

        $results = is_array($stdout) ? ($stdout['results'] ?? []) : [];
        $groups = [
            'failed_checks' => 'FAIL',
            'passed_checks' => 'PASS',
            'skipped_checks' => 'WARN',
        ];

        $findings = collect($groups)
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

        if ($findings->isNotEmpty()) {
            return $findings;
        }

        if (($context['payload']['success'] ?? null) === false || (int) ($context['payload']['return_code'] ?? 0) !== 0) {
            $rawExecutionOutput = $this->resolveCheckovExecutionOutput($context['payload']);

            if (filled($rawExecutionOutput)) {
                return collect([
                    $this->makeFinding(
                        context: $context,
                        statusBucket: 'FAIL',
                        description: $this->summarizeCheckovExecutionOutput($rawExecutionOutput),
                        recommendation: $this->buildCheckovExecutionRecommendation($rawExecutionOutput),
                        object: $context['cluster_name'] ?: 'Checkov scan execution',
                        metadata: [
                            'tool' => 'checkov',
                            'status' => 'EXECUTION_ERROR',
                            'section' => 'execution',
                            'resource' => $context['cluster_name'] ?: 'Checkov scan execution',
                            'object' => $context['cluster_name'] ?: 'Checkov scan execution',
                            'raw_output_excerpt' => Str::limit(preg_replace('/\s+/', ' ', $rawExecutionOutput), 1000),
                        ],
                        suggestion: 'Fix the Checkov scanner execution issue, rerun the scan, and review the findings again.',
                    ),
                ]);
            }
        }

        return $findings;
    }

    protected function resolveCheckovStdoutPayload(array $payload): array|string
    {
        $candidates = [
            $payload['stdout'] ?? null,
            $payload['partial_results'] ?? null,
            $payload['stderr'] ?? null,
        ];

        foreach ($candidates as $candidate) {
            if (is_array($candidate) && isset($candidate['results'])) {
                return $candidate;
            }

            if (! is_string($candidate) || blank(trim($candidate))) {
                continue;
            }

            $decodedCandidate = $this->decodeCheckovPayloadString($candidate);

            if (is_array($decodedCandidate)) {
                return $decodedCandidate;
            }
        }

        $embeddedPayload = $this->findEmbeddedCheckovPayloadInValue($payload);

        if (is_array($embeddedPayload)) {
            return $embeddedPayload;
        }

        foreach ($candidates as $candidate) {
            if (is_string($candidate) && filled(trim($candidate))) {
                return $candidate;
            }
        }

        return [];
    }

    protected function extractEmbeddedCheckovPayload(string $stdout): ?array
    {
        $markers = [
            '{"check_type":',
            "{\n    \"check_type\":",
            "{\r\n    \"check_type\":",
        ];

        $start = null;

        foreach ($markers as $marker) {
            $position = strpos($stdout, $marker);

            if ($position !== false) {
                $start = $position;
                break;
            }
        }

        if ($start === null) {
            return null;
        }

        $candidate = substr($stdout, $start);
        $decoded = json_decode($candidate, true);

        if (is_array($decoded) && isset($decoded['results'])) {
            return $decoded;
        }

        return null;
    }

    protected function decodeCheckovPayloadString(string $payload): ?array
    {
        $decoded = $this->decodeToolPayloadString($payload);

        if (is_array($decoded) && isset($decoded['results'])) {
            return $decoded;
        }

        $embeddedPayload = $this->extractEmbeddedCheckovPayload($payload);

        if (is_array($embeddedPayload) && isset($embeddedPayload['results'])) {
            return $embeddedPayload;
        }

        return null;
    }

    protected function findEmbeddedCheckovPayloadInValue(mixed $value): ?array
    {
        if (is_string($value) && filled(trim($value))) {
            return $this->decodeCheckovPayloadString($value);
        }

        if (! is_array($value)) {
            return null;
        }

        foreach ($value as $nestedValue) {
            $embeddedPayload = $this->findEmbeddedCheckovPayloadInValue($nestedValue);

            if (is_array($embeddedPayload)) {
                return $embeddedPayload;
            }
        }

        return null;
    }

    protected function resolveCheckovExecutionOutput(array $payload): string
    {
        foreach (['stdout', 'stderr', 'partial_results'] as $key) {
            $value = $payload[$key] ?? null;

            if (is_string($value) && filled(trim($value))) {
                return $value;
            }
        }

        return '';
    }

    protected function decodeToolPayloadString(string $payload): ?array
    {
        $decoded = $this->decodeSamplePayload($payload);

        if (is_array($decoded)) {
            return $decoded;
        }

        $pseudoJson = $this->normalizePseudoJsonString($payload);

        if ($pseudoJson === null) {
            return null;
        }

        $decodedPseudoJson = json_decode($pseudoJson, true);

        return is_array($decodedPseudoJson) ? $decodedPseudoJson : null;
    }

    protected function summarizeCheckovExecutionOutput(string $stdout): string
    {
        $normalized = trim((string) preg_replace('/\s+/', ' ', $stdout));

        if (Str::contains(Str::lower($normalized), 'forbidden')) {
            return 'Checkov scan could not collect Kubernetes resources because the scanner service account does not have sufficient RBAC permissions.';
        }

        return Str::limit($normalized, 240);
    }

    protected function buildCheckovExecutionRecommendation(string $stdout): string
    {
        if (Str::contains(Str::lower($stdout), 'forbidden')) {
            return 'Grant the Checkov scanner service account the required Kubernetes RBAC permissions for the resources it needs to list, then rerun the scan.';
        }

        return 'Review the Checkov execution output, fix the scanner runtime issue, and rerun the scan.';
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
        return $this->extractNmapEntries($context['payload']['stdout'] ?? $context['payload'])
            ->flatMap(function ($scanEntry, string $scanKey) use ($context): array {
                if (! is_array($scanEntry)) {
                    return [];
                }

                if (is_string($scanEntry) && filled(trim($scanEntry))) {
                    $scanEntry = $this->decodeSamplePayload($scanEntry) ?? $scanEntry;
                }

                if (! is_array($scanEntry)) {
                    return [];
                }

                $nmapRun = $scanEntry['nmaprun'] ?? $scanEntry;

                if (! is_array($nmapRun)) {
                    return [];
                }

                $host = $nmapRun['host'] ?? [];
                $address = data_get($host, 'address.@addr');
                $hostname = data_get($host, 'hostnames.hostname.@name');
                $ports = data_get($host, 'ports.port', []);
                $ports = is_array($ports) && array_is_list($ports) ? $ports : (filled($ports) ? [$ports] : []);

                return collect($ports)
                    ->filter(fn ($port): bool => is_array($port) && Str::lower((string) data_get($port, 'state.@state')) === 'open')
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

    protected function extractNmapEntries(mixed $stdout): Collection
    {
        if (is_string($stdout) && filled(trim($stdout))) {
            $stdout = $this->decodeSamplePayload($stdout) ?? $stdout;
        }

        if (! is_array($stdout)) {
            return collect();
        }

        if (isset($stdout['nmaprun']) || isset($stdout['host']) || isset($stdout['ports'])) {
            return collect([['nmaprun' => isset($stdout['nmaprun']) ? $stdout['nmaprun'] : $stdout]]);
        }

        return collect($stdout)
            ->map(function ($entry) {
                if (is_string($entry) && filled(trim($entry))) {
                    return $this->decodeSamplePayload($entry) ?? $entry;
                }

                return $entry;
            })
            ->filter(function ($entry): bool {
                if (! is_array($entry)) {
                    return false;
                }

                return isset($entry['nmaprun']) || isset($entry['host']) || isset($entry['ports']);
            })
            ->map(function (array $entry): array {
                return isset($entry['nmaprun']) ? $entry : ['nmaprun' => $entry];
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
        $normalized = str_replace(['_', ' '], '-', $lower);

        return match (true) {
            Str::startsWith($lower, 'kubebench-'),
            Str::contains($lower, 'result-kubebench'),
            Str::contains($normalized, 'result-kube-bench') => 'kubebench',
            Str::startsWith($lower, 'kubescape-'),
            Str::contains($lower, 'result-kubescape') => 'kubescape',
            Str::startsWith($lower, 'checkov-'),
            Str::contains($lower, 'result-checkov') => 'checkov',
            Str::startsWith($lower, 'nmap'),
            Str::contains($lower, 'result-nmap') => 'nmap',
            Str::startsWith($lower, 'rbac-'),
            Str::contains($lower, 'result-rbac'),
            Str::contains($lower, 'result-rbac-tool'),
            Str::contains($normalized, 'result-rbac-tool') => 'rbac-tool',
            default => null,
        };
    }

    protected function detectToolFromPayload(array $payload): ?string
    {
        $stdout = $payload['stdout'] ?? [];
        $partialResults = $payload['partial_results'] ?? null;

        return match (true) {
            isset($stdout['Controls']) || isset($stdout['controls']) => 'kubebench',
            isset($stdout['summaryDetails'], $stdout['results']) => 'kubescape',
            (isset($stdout['summary'], $stdout['results']) && isset($stdout['check_type'])) ||
            (is_array($partialResults) && isset($partialResults['results'], $partialResults['check_type'])) => 'checkov',
            isset($stdout['nmaprun']) || isset($stdout['host']) || collect($stdout)->contains(fn ($entry): bool => is_array($entry) && (isset($entry['nmaprun']) || isset($entry['host']) || isset($entry['ports']))) => 'nmap',
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
