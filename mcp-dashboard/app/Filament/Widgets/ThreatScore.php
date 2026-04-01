<?php
namespace App\Filament\Widgets;

use App\Services\ScanService;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class ThreatScore extends StatsOverviewWidget
{
    protected int | string | array $columnSpan = 'full';

    protected int | array | null $columns = 1;

    protected function getStats(): array
    {
        $service = new ScanService();
        $data = $service->getScanData();

        $totals = $data['Totals'];

        $total = $totals['total_pass'] + $totals['total_fail'] + $totals['total_warn'];

        $score = $total > 0
            ? round(($totals['total_pass'] / $total) * 100, 2)
            : 0;

        return [
            Stat::make('Security Score', $score . '%')
                ->description('Cluster Security Level')
                ->color($score > 80 ? 'success' : ($score > 50 ? 'warning' : 'danger')),
        ];
    }
}
