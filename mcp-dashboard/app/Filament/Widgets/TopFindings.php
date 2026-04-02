<?php

namespace App\Filament\Widgets;

use App\Services\DashboardResultService;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget;
use Filament\Tables;
use Filament\Widgets\Concerns\InteractsWithPageFilters;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class TopFindings extends TableWidget
{
    use InteractsWithPageFilters;

    protected int | string | array $columnSpan = 'full';

    public static ?string $heading = 'Top Findings';

    public function table(Table $table): Table
    {
        return $table
            ->heading('Top Findings')
            ->description('Search across failed findings from your imported security tool results.')
            ->searchable()
            ->searchPlaceholder('Search task, tool, cluster, finding, remediation...')
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(10)
            ->striped()
            ->records(fn (?string $search): Collection => $this->getFilteredRecords($search))
            ->columns([
                Tables\Columns\TextColumn::make('task_identifier')
                    ->label('Scan ID')
                    ->searchable(),

                Tables\Columns\TextColumn::make('source_tool')
                    ->label('Tool')
                    ->badge()
                    ->color('primary'),

                Tables\Columns\TextColumn::make('cluster_name')
                    ->label('Cluster')
                    ->badge()
                    ->color('gray')
                    ->toggleable(),

                Tables\Columns\TextColumn::make('object_label')
                    ->label('Finding Object')
                    ->toggleable(),

                Tables\Columns\TextColumn::make('scan_finding')
                    ->label('Finding')
                    ->wrap()
                    ->grow()
                    ->extraAttributes(['class' => 'whitespace-normal']),

                Tables\Columns\TextColumn::make('recommendation')
                    ->label('Remediation')
                    ->wrap()
                    ->toggleable(),

                Tables\Columns\TextColumn::make('status')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'FAIL' => 'danger',
                        'WARN' => 'warning',
                        'PASS' => 'success',
                        default => 'gray',
                    }),
            ]);
    }

    protected function getFilteredRecords(?string $search = null): Collection
    {
        return app(DashboardResultService::class)->getTopFindings($this->pageFilters, $search)
            ->mapWithKeys(fn (array $record): array => [$record['key'] => $record]);
    }
}
