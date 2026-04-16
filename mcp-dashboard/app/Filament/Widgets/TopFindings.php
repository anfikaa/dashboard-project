<?php

namespace App\Filament\Widgets;

use App\Services\DashboardResultService;
use Filament\Actions\Action;
use Filament\Forms\Components\Textarea;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget;
use Filament\Tables;
use Filament\Widgets\Concerns\InteractsWithPageFilters;
use Illuminate\Support\Collection;

class TopFindings extends TableWidget
{
    use InteractsWithPageFilters;

    protected int | string | array $columnSpan = 'full';

    public static ?string $heading = 'Top Findings';

    public function table(Table $table): Table
    {
        return $table
            ->heading('Top Findings')
            ->description('Search across failed findings imported from task results and fallback scan parsing.')
            ->searchable()
            ->searchPlaceholder('Search scan id, tool, cluster, status, finding, remediation...')
            ->defaultSort('scanned_at', 'desc')
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(10)
            ->striped()
            ->records(fn (?string $search, ?string $sortColumn, ?string $sortDirection): Collection => $this->getFilteredRecords($search, $sortColumn, $sortDirection))
            ->columns([
                Tables\Columns\TextColumn::make('scan_id')
                    ->label('Scan ID')
                    ->searchable()
                    ->wrap()
                    ->tooltip(fn (array $record): ?string => filled($record['local_task_id'] ?? null) ? 'Local Task ID: ' . $record['local_task_id'] : null)
                    ->extraHeaderAttributes(['style' => 'width: 18rem;'])
                    ->extraAttributes(['style' => 'width: 18rem; min-width: 18rem; max-width: 18rem; white-space: normal; overflow-wrap: anywhere; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; vertical-align: top;']),

                Tables\Columns\TextColumn::make('local_task_id')
                    ->label('Task Ref')
                    ->toggleable()
                    ->placeholder('-')
                    ->tooltip(fn ($state): ?string => filled($state) ? 'Local Laravel task reference' : null)
                    ->extraHeaderAttributes(['style' => 'width: 11rem;'])
                    ->extraAttributes(['style' => 'width: 11rem; min-width: 11rem;']),

                Tables\Columns\TextColumn::make('scanned_at')
                    ->label('Datetime')
                    ->formatStateUsing(fn ($state, array $record): string => $record['scan_datetime'] ?? '-')
                    ->sortable()
                    ->extraHeaderAttributes(['style' => 'width: 11rem;'])
                    ->extraAttributes(['style' => 'width: 11rem; min-width: 11rem;']),

                Tables\Columns\TextColumn::make('scan_status')
                    ->label('Scan Status')
                    ->badge()
                    ->color(fn (string $state): string => match (strtoupper($state)) {
                        'COMPLETED' => 'success',
                        'FAILED', 'FAIL' => 'danger',
                        default => 'gray',
                    })
                    ->extraHeaderAttributes(['style' => 'width: 9rem;'])
                    ->extraAttributes(['style' => 'width: 9rem; min-width: 9rem;']),

                Tables\Columns\TextColumn::make('source_tool')
                    ->label('Tool')
                    ->badge()
                    ->color('primary')
                    ->extraHeaderAttributes(['style' => 'width: 8rem;'])
                    ->extraAttributes(['style' => 'width: 8rem; min-width: 8rem;']),

                Tables\Columns\TextColumn::make('cluster_name')
                    ->label('Cluster')
                    ->badge()
                    ->color('gray')
                    ->toggleable()
                    ->extraHeaderAttributes(['style' => 'width: 10rem;'])
                    ->extraAttributes(['style' => 'width: 10rem; min-width: 10rem;']),

                Tables\Columns\TextColumn::make('object_label')
                    ->label('Finding Object')
                    ->toggleable()
                    ->wrap()
                    ->extraHeaderAttributes(['style' => 'width: 14rem;'])
                    ->extraAttributes(['style' => 'width: 14rem; min-width: 14rem; max-width: 14rem; white-space: normal;']),

                Tables\Columns\TextColumn::make('scan_finding')
                    ->label('Finding')
                    ->limit(240)
                    ->tooltip(fn (array $record): ?string => filled($record['scan_finding'] ?? null) ? $record['scan_finding'] : null)
                    ->action(
                        Action::make('viewFinding')
                            ->modalHeading('Finding Preview')
                            ->fillForm(fn (array $record): array => [
                                'finding_preview' => $record['scan_finding'] ?? '',
                            ])
                            ->schema([
                                Textarea::make('finding_preview')
                                    ->label('Finding')
                                    ->rows(14)
                                    ->disabled(),
                            ])
                            ->modalWidth('4xl')
                            ->modalSubmitAction(false)
                            ->modalCancelAction(fn (Action $action) => $action->label('Close'))
                    )
                    ->wrap()
                    ->extraHeaderAttributes(['style' => 'width: 18rem;'])
                    ->extraAttributes(['style' => 'width: 18rem; min-width: 18rem; max-width: 18rem; white-space: normal; vertical-align: top;']),

                Tables\Columns\TextColumn::make('recommendation')
                    ->label('Remediation')
                    ->limit(50)
                    ->tooltip(fn (array $record): ?string => filled($record['recommendation'] ?? null) ? $record['recommendation'] : null)
                    ->action(
                        Action::make('viewRemediation')
                            ->modalHeading('Full Remediation')
                            ->fillForm(fn (array $record): array => [
                                'remediation' => $record['recommendation'] ?? '',
                            ])
                            ->schema([
                                Textarea::make('remediation')
                                    ->label('Remediation Guidance')
                                    ->rows(10)
                                    ->disabled(),
                            ])
                            ->modalWidth('3xl')
                            ->modalSubmitAction(false)
                            ->modalCancelAction(fn (Action $action) => $action->label('Close'))
                    )
                    ->toggleable()
                    ->extraHeaderAttributes(['style' => 'width: 12rem;'])
                    ->extraAttributes(['style' => 'width: 12rem; min-width: 12rem; max-width: 12rem; white-space: normal; vertical-align: top; cursor: pointer;']),

                Tables\Columns\TextColumn::make('status')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'FAIL' => 'danger',
                        'WARN' => 'warning',
                        'PASS' => 'success',
                        default => 'gray',
                    })
                    ->extraHeaderAttributes(['style' => 'width: 7rem;'])
                    ->extraAttributes(['style' => 'width: 7rem; min-width: 7rem;']),
            ]);
    }

    protected function getFilteredRecords(?string $search = null, ?string $sortColumn = null, ?string $sortDirection = null): Collection
    {
        $records = app(DashboardResultService::class)->getTopFindings($this->pageFilters, $search);

        if (filled($sortColumn)) {
            $records = $records
                ->sortBy(
                    fn (array $record): mixed => $record[$sortColumn] ?? null,
                    options: SORT_NATURAL,
                    descending: $sortDirection === 'desc',
                )
                ->values();
        }

        return $records->mapWithKeys(fn (array $record): array => [$record['key'] => $record]);
    }
}
