<?php

namespace App\Filament\Resources;

use App\Filament\Resources\SecurityTaskResultResource\Pages;
use App\Models\SecurityTaskResult;
use Filament\Actions\Action;
use Filament\Forms\Components\DatePicker;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\HtmlString;

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
                Tables\Columns\TextColumn::make('source_tool')
                    ->label('Tool')
                    ->badge()
                    ->color('primary'),
                Tables\Columns\TextColumn::make('cluster_name')
                    ->label('Cluster')
                    ->badge()
                    ->color('gray')
                    ->toggleable(),
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
                Tables\Columns\TextColumn::make('finding_object')
                    ->label('Finding Object')
                    ->state(fn (SecurityTaskResult $record): HtmlString => static::renderFindingObjectCard($record))
                    ->wrap()
                    ->html()
                    ->toggleable(),
                Tables\Columns\TextColumn::make('recommendation')
                    ->label('Remediation Recommendation')
                    ->wrap()
                    ->searchable(),
                Tables\Columns\TextColumn::make('suggestion')
                    ->label('Suggestion')
                    ->wrap()
                    ->toggleable(isToggledHiddenByDefault: false),
            ])
            ->filters([
                Tables\Filters\SelectFilter::make('task_identifier')
                    ->label('Task ID')
                    ->options(fn (): array => SecurityTaskResult::query()
                        ->whereNotNull('task_identifier')
                        ->distinct()
                        ->orderByDesc('task_identifier')
                        ->pluck('task_identifier', 'task_identifier')
                        ->all()),
                Tables\Filters\SelectFilter::make('source_tool')
                    ->label('Tool')
                    ->options(fn (): array => SecurityTaskResult::query()
                        ->whereNotNull('source_tool')
                        ->distinct()
                        ->orderBy('source_tool')
                        ->pluck('source_tool', 'source_tool')
                        ->all()),
                Tables\Filters\SelectFilter::make('cluster_name')
                    ->label('Cluster')
                    ->options(fn (): array => SecurityTaskResult::query()
                        ->whereNotNull('cluster_name')
                        ->distinct()
                        ->orderBy('cluster_name')
                        ->pluck('cluster_name', 'cluster_name')
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
                Action::make('expand')
                    ->label('Expand')
                    ->icon('heroicon-o-arrows-pointing-out')
                    ->color('gray')
                    ->slideOver()
                    ->modalHeading(fn (SecurityTaskResult $record): string => 'Finding Details - ' . $record->task_identifier)
                    ->modalDescription(fn (SecurityTaskResult $record): string => 'Expanded technical context for this finding from ' . ($record->source_tool ?: 'the scan tool') . '.')
                    ->modalSubmitAction(false)
                    ->modalCancelAction(fn (Action $action) => $action->label('Close'))
                    ->modalWidth('4xl')
                    ->modalContent(fn (SecurityTaskResult $record): HtmlString => static::renderExpandedFindingContent($record)),
                Action::make('open_task')
                    ->label('Open Task')
                    ->icon('heroicon-o-arrow-top-right-on-square')
                    ->url(fn (SecurityTaskResult $record): string => SecurityTaskResource::getUrl('index') . '?search=' . urlencode($record->task_identifier)),
            ]);
    }

    protected static function renderFindingObjectCard(SecurityTaskResult $record): HtmlString
    {
        $metadata = $record->metadata ?? [];

        $title = null;

        foreach (['object', 'resource', 'resource_name', 'object_name', 'name'] as $key) {
            $value = $metadata[$key] ?? null;

            if (is_string($value) && filled($value)) {
                $title = $value;
                break;
            }

            if (is_array($value) && ! empty($value)) {
                $title = json_encode($value, JSON_UNESCAPED_SLASHES);
                break;
            }
        }

        $title ??= 'Finding context';

        $chips = array_filter([
            static::renderChip('Control', $metadata['control_id'] ?? null, 'gray'),
            static::renderChip('Test', $metadata['test_number'] ?? null, 'blue'),
            static::renderChip('Section', $metadata['section'] ?? null, 'amber'),
        ]);

        $actual = $metadata['actual'] ?? null;
        $expected = $metadata['expected'] ?? null;
        $severityTone = static::severityTone($record->severity);

        $detailRows = array_filter([
            static::renderDetailRow('Actual', $actual),
            static::renderDetailRow('Expected', $expected),
        ]);

        $html = '<div class="space-y-2">';
        $html .= '<div class="rounded-lg border px-3 py-2 ' . $severityTone['card'] . '">';
        $html .= '<div class="text-sm font-medium text-gray-950 dark:text-white">' . e($title) . '</div>';
        $html .= '<div class="mt-2"><span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-semibold ring-1 ring-inset ' . $severityTone['badge'] . '">' . e((string) $record->severity) . '</span></div>';

        if ($chips !== []) {
            $html .= '<div class="mt-2 flex flex-wrap gap-2">' . implode('', $chips) . '</div>';
        }

        if ($detailRows !== []) {
            $html .= '<div class="mt-3 space-y-1">' . implode('', $detailRows) . '</div>';
        }

        $html .= '</div>';
        $html .= '</div>';

        return new HtmlString($html);
    }

    protected static function renderExpandedFindingContent(SecurityTaskResult $record): HtmlString
    {
        $metadata = $record->metadata ?? [];
        $severityTone = static::severityTone($record->severity);

        $rows = [
            'Task ID' => $record->task_identifier,
            'Tool' => $record->source_tool,
            'Cluster' => $record->cluster_name,
            'Severity' => $record->severity,
            'Scanned At' => optional($record->scanned_at)->format('d M Y H:i:s'),
            'Finding Object' => static::resolvePrimaryObject($metadata),
            'Control ID' => $metadata['control_id'] ?? null,
            'Test Number' => $metadata['test_number'] ?? null,
            'Section' => $metadata['section'] ?? null,
            'Rule Name' => $metadata['rule_name'] ?? null,
            'File Path' => $metadata['file_path'] ?? null,
            'Actual Value' => $metadata['actual'] ?? null,
            'Expected Value' => $metadata['expected'] ?? null,
        ];

        $infoRows = '';

        foreach ($rows as $label => $value) {
            if (blank($value)) {
                continue;
            }

            if (is_array($value)) {
                $value = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            }

            $infoRows .= '<div class="grid grid-cols-1 gap-1 border-b border-gray-100 py-3 last:border-b-0 dark:border-white/10 md:grid-cols-[180px_minmax(0,1fr)]">';
            $infoRows .= '<div class="text-sm font-medium text-gray-500 dark:text-gray-400">' . e($label) . '</div>';
            $infoRows .= '<div class="text-sm text-gray-900 dark:text-gray-100">' . nl2br(e((string) $value)) . '</div>';
            $infoRows .= '</div>';
        }

        $rawMetadata = json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $html = '<div class="space-y-6">';
        $html .= '<section class="rounded-xl border p-4 ' . $severityTone['card'] . '">';
        $html .= '<div class="flex flex-wrap items-center gap-3">';
        $html .= '<h3 class="text-base font-semibold text-gray-950 dark:text-white">Finding Overview</h3>';
        $html .= '<span class="inline-flex items-center rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ' . $severityTone['badge'] . '">' . e((string) $record->severity) . '</span>';
        $html .= '</div>';
        $html .= '<p class="mt-3 text-sm leading-6 text-gray-700 dark:text-gray-200">' . e($record->scan_finding) . '</p>';
        $html .= '</section>';

        $html .= '<section class="rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-white/5">';
        $html .= '<h3 class="text-base font-semibold text-gray-950 dark:text-white">Remediation</h3>';
        $html .= '<p class="mt-3 text-sm leading-6 text-gray-700 dark:text-gray-200">' . e((string) $record->recommendation) . '</p>';
        if (filled($record->suggestion)) {
            $html .= '<div class="mt-4 rounded-lg bg-gray-50 px-3 py-3 text-sm leading-6 text-gray-700 dark:bg-white/5 dark:text-gray-200">';
            $html .= '<span class="font-semibold text-gray-900 dark:text-white">Suggestion:</span> ' . e((string) $record->suggestion);
            $html .= '</div>';
        }
        $html .= '</section>';

        $html .= '<section class="rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-white/5">';
        $html .= '<h3 class="text-base font-semibold text-gray-950 dark:text-white">Technical Context</h3>';
        $html .= '<div class="mt-3">' . $infoRows . '</div>';
        $html .= '</section>';

        $html .= '<section class="rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-white/5">';
        $html .= '<h3 class="text-base font-semibold text-gray-950 dark:text-white">Raw Finding Metadata</h3>';
        $html .= '<pre class="mt-3 overflow-x-auto rounded-lg bg-gray-950 p-4 text-xs leading-6 text-green-200">' . e((string) $rawMetadata) . '</pre>';
        $html .= '</section>';
        $html .= '</div>';

        return new HtmlString($html);
    }

    protected static function severityTone(?string $severity): array
    {
        return match (strtoupper((string) $severity)) {
            'FAIL', 'CRITICAL', 'HIGH' => [
                'card' => 'border-danger-200 bg-danger-50 dark:border-danger-500/30 dark:bg-danger-500/10',
                'badge' => 'bg-danger-50 text-danger-700 ring-danger-200 dark:bg-danger-500/10 dark:text-danger-200 dark:ring-danger-500/30',
            ],
            'WARN', 'MEDIUM' => [
                'card' => 'border-warning-200 bg-warning-50 dark:border-warning-500/30 dark:bg-warning-500/10',
                'badge' => 'bg-warning-50 text-warning-700 ring-warning-200 dark:bg-warning-500/10 dark:text-warning-200 dark:ring-warning-500/30',
            ],
            'PASS', 'LOW' => [
                'card' => 'border-success-200 bg-success-50 dark:border-success-500/30 dark:bg-success-500/10',
                'badge' => 'bg-success-50 text-success-700 ring-success-200 dark:bg-success-500/10 dark:text-success-200 dark:ring-success-500/30',
            ],
            default => [
                'card' => 'border-gray-200 bg-white dark:border-white/10 dark:bg-white/5',
                'badge' => 'bg-gray-50 text-gray-700 ring-gray-200 dark:bg-gray-500/10 dark:text-gray-200 dark:ring-gray-500/30',
            ],
        };
    }

    protected static function resolvePrimaryObject(array $metadata): ?string
    {
        foreach (['object', 'resource', 'resource_name', 'object_name', 'name'] as $key) {
            $value = $metadata[$key] ?? null;

            if (is_string($value) && filled($value)) {
                return $value;
            }
        }

        return null;
    }

    protected static function renderChip(string $label, mixed $value, string $tone): ?string
    {
        if (blank($value)) {
            return null;
        }

        $toneClasses = match ($tone) {
            'blue' => 'bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/10 dark:text-blue-200 dark:ring-blue-500/30',
            'amber' => 'bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/30',
            default => 'bg-gray-50 text-gray-700 ring-gray-200 dark:bg-gray-500/10 dark:text-gray-200 dark:ring-gray-500/30',
        };

        return sprintf(
            '<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset %s">%s: %s</span>',
            $toneClasses,
            e($label),
            e((string) $value),
        );
    }

    protected static function renderDetailRow(string $label, mixed $value): ?string
    {
        if (blank($value)) {
            return null;
        }

        if (is_array($value)) {
            $value = json_encode($value, JSON_UNESCAPED_SLASHES);
        }

        return sprintf(
            '<div class="text-xs leading-5 text-gray-600 dark:text-gray-300"><span class="font-semibold text-gray-800 dark:text-gray-100">%s:</span> %s</div>',
            e($label),
            e((string) $value),
        );
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListSecurityTaskResults::route('/'),
        ];
    }
}
