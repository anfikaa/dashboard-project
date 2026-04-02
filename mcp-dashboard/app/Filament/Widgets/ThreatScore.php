<?php
namespace App\Filament\Widgets;

use App\Services\DashboardResultService;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use Filament\Widgets\Concerns\InteractsWithPageFilters;

class ThreatScore extends StatsOverviewWidget
{
    use InteractsWithPageFilters;

    protected int | string | array $columnSpan = [
        'default' => 1,
        'md' => 1,
    ];

    protected int | array | null $columns = 1;

    protected function getStats(): array
    {
        $totals = app(DashboardResultService::class)->summarize($this->pageFilters);

        $total = ($totals['PASS'] ?? 0) + ($totals['FAIL'] ?? 0) + ($totals['WARN'] ?? 0);

        $score = $total > 0
            ? round((($totals['PASS'] ?? 0) / $total) * 100, 2)
            : 0;

        return [
            Stat::make('Security Score', $score . '%')
                ->description('Filtered security posture score')
                ->color($score > 80 ? 'success' : ($score > 50 ? 'warning' : 'danger')),
        ];
    }
}
