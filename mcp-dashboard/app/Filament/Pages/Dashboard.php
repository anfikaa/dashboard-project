<?php

namespace App\Filament\Pages;

use App\Services\DashboardResultService;
use Filament\Forms\Components\Select;
use Filament\Pages\Dashboard as BaseDashboard;
use Filament\Pages\Dashboard\Concerns\HasFiltersForm;
use Filament\Support\Enums\Width;
use Illuminate\Contracts\Support\Htmlable;
use Filament\Schemas\Schema;

class Dashboard extends BaseDashboard
{
    use HasFiltersForm;

    protected Width | string | null $maxContentWidth = Width::Full;

    public function getHeading(): string | Htmlable | null
    {
        return null;
    }

    public function getSubheading(): string | Htmlable | null
    {
        return 'Overview of security findings parsed directly from the configured scan source.';
    }

    protected function getHeaderWidgets(): array
    {
        return [];
    }

    public function getWidgets(): array
    {
        return [
            \App\Filament\Widgets\ScanOverview::class,
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

    public function filtersForm(Schema $schema): Schema
    {
        return $schema->components([
            Select::make('task_identifier')
                ->label('Scan ID')
                ->options(fn (): array => app(DashboardResultService::class)->getDashboardOptions('scan_id'))
                ->searchable()
                ->preload()
                ->placeholder('All scans'),
            Select::make('source_tool')
                ->label('Tool')
                ->options(fn (): array => app(DashboardResultService::class)->getDashboardOptions('tool'))
                ->searchable()
                ->preload()
                ->placeholder('All tools'),
            Select::make('cluster_name')
                ->label('Cluster')
                ->options(fn (): array => app(DashboardResultService::class)->getDashboardOptions('cluster_name'))
                ->searchable()
                ->preload()
                ->placeholder('All clusters'),
        ]);
    }
}
