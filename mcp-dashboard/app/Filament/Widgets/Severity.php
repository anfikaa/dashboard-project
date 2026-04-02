<?php
namespace App\Filament\Widgets;

use App\Services\DashboardResultService;
use Filament\Widgets\Widget;
use Filament\Widgets\Concerns\InteractsWithPageFilters;

class Severity extends Widget
{
    use InteractsWithPageFilters;

    protected string $view = 'filament.widgets.severity-widget';

    protected int | string | array $columnSpan = [
        'default' => 1,
        'md' => 1,
    ];

    protected function getViewData(): array
    {
        $totals = app(DashboardResultService::class)->summarize($this->pageFilters);

        return [
            'fail' => $totals['FAIL'] ?? 0,
            'warn' => $totals['WARN'] ?? 0,
            'pass' => $totals['PASS'] ?? 0,
        ];
    }
}
