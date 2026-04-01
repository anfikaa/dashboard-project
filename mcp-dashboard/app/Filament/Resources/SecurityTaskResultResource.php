<?php

namespace App\Filament\Resources;

use App\Filament\Resources\SecurityTaskResultResource\Pages;
use App\Models\SecurityTask;
use App\Models\SecurityTaskResult;
use Filament\Actions\Action;
use Filament\Forms\Components\DatePicker;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;

class SecurityTaskResultResource extends Resource
{
    protected static ?string $model = SecurityTaskResult::class;

    protected static string | \BackedEnum | null $navigationIcon = 'heroicon-o-table-cells';

    protected static \UnitEnum | string | null $navigationGroup = 'Security Operations';

    public static function form(Schema $schema): Schema
    {
        return $schema;
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with('task');

        if ($taskIdentifier = request()->query('task')) {
            $query->where('task_identifier', $taskIdentifier);
        }

        return $query;
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('scanned_at', 'desc')
            ->columns([
                Tables\Columns\TextColumn::make('task_identifier')
                    ->label('Task ID')
                    ->searchable()
                    ->copyable(),
                Tables\Columns\TextColumn::make('scanned_at')
                    ->label('Datetime')
                    ->dateTime('d M Y H:i')
                    ->sortable(),
                Tables\Columns\TextColumn::make('severity')
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'FAIL' => 'danger',
                        'WARN' => 'warning',
                        'PASS' => 'success',
                        default => 'gray',
                    }),
                Tables\Columns\TextColumn::make('scan_finding')
                    ->label('Scan Findings')
                    ->wrap()
                    ->searchable(),
                Tables\Columns\TextColumn::make('recommendation')
                    ->label('Recommendation / Suggestion')
                    ->state(fn (SecurityTaskResult $record): string => trim($record->recommendation . ' ' . $record->suggestion))
                    ->wrap()
                    ->searchable(),
            ])
            ->filters([
                Tables\Filters\SelectFilter::make('task_identifier')
                    ->label('Task ID')
                    ->options(fn (): array => SecurityTask::query()
                        ->orderByDesc('created_at')
                        ->pluck('task_id', 'task_id')
                        ->all()),
                Tables\Filters\Filter::make('scanned_at')
                    ->label('Scanned Time')
                    ->schema([
                        DatePicker::make('from'),
                        DatePicker::make('until'),
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return $query
                            ->when(
                                $data['from'] ?? null,
                                fn (Builder $query, $date): Builder => $query->whereDate('scanned_at', '>=', $date),
                            )
                            ->when(
                                $data['until'] ?? null,
                                fn (Builder $query, $date): Builder => $query->whereDate('scanned_at', '<=', $date),
                            );
                    }),
            ])
            ->actions([
                Action::make('open_task')
                    ->label('Open Task')
                    ->icon('heroicon-o-arrow-top-right-on-square')
                    ->url(fn (SecurityTaskResult $record): string => SecurityTaskResource::getUrl('index') . '?search=' . urlencode($record->task_identifier)),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListSecurityTaskResults::route('/'),
        ];
    }
}
