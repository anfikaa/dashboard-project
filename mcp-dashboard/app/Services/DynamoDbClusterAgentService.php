<?php

namespace App\Services;

use App\Models\ClusterAgent;
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

class DynamoDbClusterAgentService
{
    public function syncToDatabase(bool $forceRefresh = false): int
    {
        $agents = $this->getAgents($forceRefresh);
        $activeKeys = [];

        foreach ($agents as $agent) {
            $activeKeys[] = Str::lower($agent['cluster_name'] . '|' . $agent['label']);

            ClusterAgent::updateOrCreate(
                [
                    'cluster_name' => $agent['cluster_name'],
                    'label' => $agent['label'],
                ],
                [
                    'name' => $agent['label'],
                    'provider' => $agent['provider'],
                    'region' => $agent['region'],
                    'status' => $agent['status'],
                    'available_tools' => $agent['available_tools'],
                    'is_active' => true,
                    'endpoint' => null,
                    'last_seen_at' => now(),
                ],
            );
        }

        ClusterAgent::query()
            ->get()
            ->reject(fn (ClusterAgent $agent): bool => in_array(
                Str::lower($agent->cluster_name . '|' . $agent->label),
                $activeKeys,
                true,
            ))
            ->each
            ->delete();

        return count($agents);
    }

    public function getAgents(bool $forceRefresh = false): array
    {
        $ttl = max(1, (int) env('CLUSTER_AGENT_CACHE_TTL_SECONDS', 60));
        $cacheKey = $this->cacheKey();

        if ($forceRefresh) {
            Cache::forget($cacheKey);
        }

        return Cache::remember($cacheKey, now()->addSeconds($ttl), function (): array {
            $client = $this->makeClient();
            $marshaler = new Marshaler();
            $table = $this->tableName();
            $items = [];
            $lastEvaluatedKey = null;

            do {
                $params = [
                    'TableName' => $table,
                ];

                if ($lastEvaluatedKey !== null) {
                    $params['ExclusiveStartKey'] = $lastEvaluatedKey;
                }

                $result = $client->scan($params);

                foreach (($result['Items'] ?? []) as $item) {
                    $record = $marshaler->unmarshalItem($item);
                    $normalized = $this->normalizeAgentRecord($record);

                    if ($normalized !== null) {
                        $items[] = $normalized;
                    }
                }

                $lastEvaluatedKey = $result['LastEvaluatedKey'] ?? null;
            } while ($lastEvaluatedKey !== null);

            return collect($items)
                ->unique(fn (array $agent): string => Str::lower($agent['cluster_name'] . '|' . $agent['label']))
                ->sortBy(['cluster_name', 'label'])
                ->values()
                ->all();
        });
    }

    protected function cacheKey(): string
    {
        return 'cluster-agents.dynamodb.' . md5(json_encode([
            'table' => $this->tableName(),
            'region' => env('AWS_DYNAMODB_REGION'),
        ]));
    }

    protected function normalizeAgentRecord(array $record): ?array
    {
        $clusterName = $this->firstString($record, ['cluster_name', 'cluster', 'agent_cluster']);
        $label = $this->firstString($record, ['label', 'name', 'agent_name']);
        $provider = $this->firstString($record, ['provider', 'cloud_provider']);
        $region = $this->firstString($record, ['region', 'aws_region']);
        $status = $this->firstString($record, ['status', 'health_status', 'agent_status']);
        $tools = $record['tools'] ?? $record['available_tools'] ?? [];

        if (blank($clusterName) || blank($label)) {
            return null;
        }

        return [
            'cluster_name' => $clusterName,
            'label' => $label,
            'provider' => $provider ?: 'Unknown',
            'region' => $region ?: 'Unknown',
            'status' => $status ?: 'unknown',
            'available_tools' => collect($this->normalizeTools($tools))
                ->filter()
                ->unique()
                ->values()
                ->all(),
        ];
    }

    protected function normalizeTools(mixed $tools): array
    {
        if (is_string($tools)) {
            return collect(preg_split('/\s*,\s*/', $tools) ?: [])
                ->map(fn ($tool): ?string => $this->normalizeToolName($tool))
                ->filter()
                ->values()
                ->all();
        }

        if (is_array($tools)) {
            if (! array_is_list($tools)) {
                return collect($tools)
                    ->filter(fn ($enabled): bool => filter_var($enabled, FILTER_VALIDATE_BOOL) || $enabled === true || $enabled === 1)
                    ->keys()
                    ->map(fn ($tool): ?string => $this->normalizeToolName($tool))
                    ->values()
                    ->all();
            }

            return collect($tools)
                ->map(fn ($tool): ?string => $this->normalizeToolName(is_scalar($tool) ? (string) $tool : json_encode($tool)))
                ->filter()
                ->values()
                ->all();
        }

        return [];
    }

    protected function firstString(array $record, array $keys): ?string
    {
        foreach ($keys as $key) {
            $value = data_get($record, $key);

            if (is_string($value) && filled($value)) {
                return $value;
            }
        }

        return null;
    }

    protected function normalizeToolName(mixed $tool): ?string
    {
        if (! is_scalar($tool)) {
            return null;
        }

        $value = Str::of((string) $tool)
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
            'rbac', 'rbac-tool', 'rbac_tool' => 'rbac-tool',
            'n-map', 'nmap' => 'nmap',
            'check-ov', 'checkov' => 'checkov',
            default => $value,
        };
    }

    protected function makeClient(): DynamoDbClient
    {
        $config = [
            'version' => 'latest',
            'region' => env('AWS_DYNAMODB_REGION', env('AWS_DEFAULT_REGION')),
        ];

        if (filled(env('AWS_DYNAMODB_ENDPOINT'))) {
            $config['endpoint'] = env('AWS_DYNAMODB_ENDPOINT');
        }

        return new DynamoDbClient($config);
    }

    protected function tableName(): string
    {
        return (string) env('CLUSTER_AGENT_DYNAMODB_TABLE', 'intern_cluster_register');
    }
}
