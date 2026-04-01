<?php
namespace App\Filament\Widgets;

use App\Services\ScanService;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class ScanStats extends StatsOverviewWidget
{
    protected function getStats(): array
    {
        $service = new ScanService();
        $data = $service->getScanData();

        $totals = $data['Totals'] ?? [];

        return [
            Stat::make('PASS', $totals['total_pass'] ?? 0)
                ->color('success')
                ->description('Secure checks'),

            Stat::make('FAIL', $totals['total_fail'] ?? 0)
                ->color('danger')
                ->description('Critical issues'),

            Stat::make('WARN', $totals['total_warn'] ?? 0)
                ->color('warning')
                ->description('Needs review'),
        ];
    }
}