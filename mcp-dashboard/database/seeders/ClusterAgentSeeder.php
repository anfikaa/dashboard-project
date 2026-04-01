<?php

namespace Database\Seeders;

use App\Models\ClusterAgent;
use App\Services\TaskExecutionService;
use Illuminate\Database\Seeder;

class ClusterAgentSeeder extends Seeder
{
    public function run(): void
    {
        $tools = array_keys(TaskExecutionService::getAvailableTools());

        $agents = [
            [
                'name' => 'agent-jakarta-01',
                'cluster_name' => 'prod-asia',
                'endpoint' => 'https://prod-asia.internal/agent',
                'available_tools' => $tools,
                'is_active' => true,
                'last_seen_at' => now()->subMinutes(3),
            ],
            [
                'name' => 'agent-singapore-02',
                'cluster_name' => 'staging-apac',
                'endpoint' => 'https://staging-apac.internal/agent',
                'available_tools' => ['kubebench', 'kubescape', 'rbac-tool'],
                'is_active' => true,
                'last_seen_at' => now()->subMinutes(9),
            ],
            [
                'name' => 'agent-lab-03',
                'cluster_name' => 'security-lab',
                'endpoint' => 'https://security-lab.internal/agent',
                'available_tools' => ['nmap', 'trivy', 'kube-hunter'],
                'is_active' => false,
                'last_seen_at' => now()->subHours(6),
            ],
        ];

        foreach ($agents as $agent) {
            ClusterAgent::updateOrCreate(
                ['name' => $agent['name']],
                $agent,
            );
        }
    }
}
