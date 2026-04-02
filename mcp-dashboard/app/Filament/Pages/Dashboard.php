<?php

namespace App\Filament\Pages;

use App\Models\ClusterAgent;
use App\Models\SecurityTask;
use App\Models\SecurityTaskResult;
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
        return 'Overview of security findings from stored task results. Use filters to slice by scan, tool, or cluster.';
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

    public function filtersForm(Schema $schema): Schema
    {
        return $schema->components([
            Select::make('task_identifier')
                ->label('Scan / Task ID')
                ->options(fn (): array => SecurityTask::query()
                    ->orderByDesc('created_at')
                    ->pluck('task_id', 'task_id')
                    ->all())
                ->searchable()
                ->preload()
                ->placeholder('All scans'),
            Select::make('source_tool')
                ->label('Tool')
                ->options(fn (): array => SecurityTaskResult::query()
                    ->whereNotNull('source_tool')
                    ->distinct()
                    ->orderBy('source_tool')
                    ->pluck('source_tool', 'source_tool')
                    ->all())
                ->searchable()
                ->preload()
                ->placeholder('All tools'),
            Select::make('cluster_name')
                ->label('Cluster')
                ->options(fn (): array => ClusterAgent::query()
                    ->whereNotNull('cluster_name')
                    ->distinct()
                    ->orderBy('cluster_name')
                    ->pluck('cluster_name', 'cluster_name')
                    ->all())
                ->searchable()
                ->preload()
                ->placeholder('All clusters'),
        ]);
    }
}
