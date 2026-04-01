<?php

namespace App\Services;

class ScanService
{
    /**
     * Load scan result from JSON file and normalize stdout into usable array.
     * Handles Python-style dict string into valid JSON.
     */
    public function getScanData(): array
    {
        $path = storage_path('app/scan/results.json');

        if (!file_exists($path)) {
            throw new \Exception('Scan result file not found');
        }

        $json = file_get_contents($path);
        $data = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Invalid JSON file: ' . json_last_error_msg());
        }

        if (!isset($data['stdout']) || !is_array($data['stdout'])) {
            throw new \Exception('stdout is missing or not properly formatted');
        }

        return $data['stdout'];
    }


    /**
     * Extract all test results into flat array for UI rendering.
     * Transforms nested Controls → tests → results into single list.
     */
    public function extractFindings(array $scanData): array
{
    $results = [];

    foreach ($scanData['Controls'] as $control) {
        foreach ($control['tests'] as $test) {
            foreach ($test['results'] as $index => $item) {

                $results[] = [
                    // 🔥 WAJIB: unique key
                    'key' => $control['id'] . '-' . $item['test_number'] . '-' . $index,

                    'control_id'     => $control['id'],
                    'section'        => $test['section'],
                    'description'    => $item['test_desc'],
                    'test_number'    => $item['test_number'],
                    'status'         => $item['status'],
                    'remediation'    => $item['remediation'],
                    'expected'       => $item['expected_result'],
                    'actual'         => $item['actual_value'],
                    'scored'         => $item['scored'],
                ];
            }
        }
    }

    return $results;
}

    /**
     * Build summary counts for dashboard visualization.
     */
    public function summarize($findings)
    {
        $summary = [
            'PASS' => 0,
            'FAIL' => 0,
            'WARN' => 0,
        ];

        foreach ($findings as $f) {
            if (isset($summary[$f['status']])) {
                $summary[$f['status']]++;
            }
        }

        return $summary;
    }

    private function sanitizePythonDict($input)
{
    // 🔥 Step 1: escape inner double quotes inside values
    $input = preg_replace_callback(
        '/"([^"]*?)"/s',
        function ($matches) {
            $value = $matches[1];

            // escape inner quotes
            $value = str_replace('"', '\"', $value);

            return '"' . $value . '"';
        },
        $input
    );

    // 🔥 Step 2: replace single quotes → double quotes
    $input = str_replace("'", '"', $input);

    return $input;
}

public function parseStdout($stdout)
{
    // 🔹 Step 1: sanitize basic
    #$clean = $this->sanitizePythonDict($stdout);

    // 🔥 Step 2: fallback escape (TARUH DI SINI)
    #$clean = preg_replace_callback('/(?<=: )"([^"]*)"(?!,)/', function ($matches) {
    #return '"' . addslashes($matches[1]) . '"';
#}, $clean);

    // 🔹 Step 3: decode
    $decoded = json_decode(json_encode($stdout), true);

    if (!$decoded) {
        throw new \Exception("Still failed parsing. Sample ");
    }

    return $decoded;
}

}