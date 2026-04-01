<?php

namespace App\Filament\Widgets;

use App\Services\ScanService;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget;
use Filament\Tables;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class TopFindings extends TableWidget
{
    protected int | string | array $columnSpan = 'full';

    public static ?string $heading = 'Top Findings';

    public function table(Table $table): Table
    {
        return $table
            ->heading('Top Findings')
            ->description('Search across failed findings from your imported security tool results.')
            ->searchable()
            ->searchPlaceholder('Search findings, control ID, section, remediation...')
            ->paginated([10, 25, 50])
            ->defaultPaginationPageOption(10)
            ->striped()
            ->records(fn (?string $search): Collection => $this->getFilteredRecords($search))
            ->columns([
                Tables\Columns\TextColumn::make('test_number')
                    ->label('ID')
                    ->sortable(),

                Tables\Columns\TextColumn::make('control_id')
                    ->label('Control')
                    ->badge()
                    ->color('gray'),

                Tables\Columns\TextColumn::make('section')
                    ->label('Section')
                    ->toggleable(),

                Tables\Columns\TextColumn::make('description')
                    ->label('Description')
                    ->wrap()
                    ->grow()
                    ->extraAttributes(['class' => 'whitespace-normal']),

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

    public function getTableRecordKey(Model | array $record): string
    {
        return $record['key'];
    }

    protected function getFilteredRecords(?string $search = null): Collection
    {
        $service = new ScanService();
        $data = $service->getScanData();
        $findings = collect($service->extractFindings($data))
            ->where('status', 'FAIL')
            ->values();

        if (blank($search)) {
            return $findings;
        }

        $needle = Str::lower(trim($search));

        return $findings
            ->filter(function (array $finding) use ($needle): bool {
                $haystack = Str::lower(implode(' ', [
                    $finding['test_number'] ?? '',
                    $finding['control_id'] ?? '',
                    $finding['section'] ?? '',
                    $finding['description'] ?? '',
                    $finding['remediation'] ?? '',
                    $finding['expected'] ?? '',
                    $finding['actual'] ?? '',
                ]));

                return Str::contains($haystack, $needle);
            })
            ->values();
    }
}
