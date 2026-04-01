<?php

namespace App\Filament\Widgets;

use App\Services\ScanService;
use Filament\Widgets\ChartWidget;

class ScanOverview extends ChartWidget
{
    protected ?string $heading = 'Scan Summary';

    protected int | string | array $columnSpan = [
        'default' => 1,
        'md' => 1,
    ];

    protected ?string $maxHeight = '320px';

    protected function getData(): array
    {
        $service = new ScanService();
        $data = $service->getScanData();

        $totals = $data['Totals'] ?? [
            'total_pass' => 0,
            'total_fail' => 0,
            'total_warn' => 0,
        ];

        return [
            'datasets' => [
                [
                    'data' => [
                        $totals['total_pass'],
                        $totals['total_fail'],
                        $totals['total_warn'],
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
