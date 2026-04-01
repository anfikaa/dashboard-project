<?php

namespace App\Filament\Pages;

use Filament\Pages\Dashboard as BaseDashboard;
use Filament\Support\Enums\Width;
use Illuminate\Contracts\Support\Htmlable;

class Dashboard extends BaseDashboard
{
    protected Width | string | null $maxContentWidth = Width::Full;

    public function getHeading(): string | Htmlable | null
    {
        return null;
    }

    public function getSubheading(): string | Htmlable | null
    {
        return null;
    }

    protected function getHeaderWidgets(): array
    {
        return [];
    }

    public function getWidgets(): array
    {
        return [
            \App\Filament\Widgets\ScanOverview::class,
            \App\Filament\Widgets\Severity::class,
            \App\Filament\Widgets\ThreatScore::class,
            \App\Filament\Widgets\TopFindings::class,
        ];
    }

    public function getColumns(): int | array
    {
        return [
            'default' => 1,
            'md' => 2,
        ];
    }
}
