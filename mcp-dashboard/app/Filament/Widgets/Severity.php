<?php
namespace App\Filament\Widgets;

use App\Services\ScanService;
use Filament\Widgets\Widget;

class Severity extends Widget
{
    protected string $view = 'filament.widgets.severity-widget';

    protected int | string | array $columnSpan = [
        'default' => 1,
        'md' => 1,
    ];

    protected function getViewData(): array
    {
        $service = new ScanService();
        $data = $service->getScanData();

        $totals = $data['Totals'];

        return [
            'fail' => $totals['total_fail'] ?? 0,
            'warn' => $totals['total_warn'] ?? 0,
            'pass' => $totals['total_pass'] ?? 0,
        ];
    }
}
