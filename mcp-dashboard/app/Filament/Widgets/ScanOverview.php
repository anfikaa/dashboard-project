<?php

namespace App\Filament\Widgets;

use App\Services\DashboardResultService;
use Filament\Widgets\ChartWidget;
use Filament\Widgets\Concerns\InteractsWithPageFilters;

class ScanOverview extends ChartWidget
{
    use InteractsWithPageFilters;

    protected ?string $heading = 'Scan Summary';

    protected int | string | array $columnSpan = [
        'default' => 1,
        'md' => 1,
    ];

    protected ?string $maxHeight = '320px';

    protected function getData(): array
    {
        $totals = app(DashboardResultService::class)->summarize($this->pageFilters);

        $totals = $totals ?: [
            'total_pass' => 0,
            'total_fail' => 0,
            'total_warn' => 0,
        ];

        return [
            'datasets' => [
                [
                    'data' => [
                        $totals['PASS'] ?? 0,
                        $totals['FAIL'] ?? 0,
                        $totals['WARN'] ?? 0,
                    ],
                    'backgroundColor' => [
                        '#22c55e', // green
                        '#ef4444', // red
                        '#f59e0b', // yellow
                    ],
                ],
            ],
            'labels' => ['PASS', 'FAIL', 'WARN'],
        ];
    }

    protected function getType(): string
    {
        return 'doughnut'; // 🔥 lebih modern dari pie
    }

    protected function getOptions(): array
    {
        return [
            'plugins' => [
                'legend' => [
                    'position' => 'bottom',
                ],
            ],
            'cutout' => '68%',
            'maintainAspectRatio' => false,
        ];
    }
}
