<?php

namespace App\Filament\Resources;

use App\Enums\SecurityTaskStatus;
use App\Filament\Resources\SecurityTaskResource\Pages;
use App\Models\ClusterAgent;
use App\Models\SecurityTask;
use App\Services\SecurityTaskSyncService;
use App\Services\TaskExecutionService;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Components\Utilities\Get;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;

class SecurityTaskResource extends Resource
{
    protected static ?string $model = SecurityTask::class;

    protected static string | \BackedEnum | null $navigationIcon = 'heroicon-o-clipboard-document-list';

    protected static \UnitEnum | string | null $navigationGroup = 'Security Operations';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([
            TextInput::make('title')
                ->label('Task Title')
                ->default('On-demand Security Scan')
                ->required()
                ->maxLength(255),
            Select::make('cluster_agent_id')
                ->label('Cluster Agent')
                ->options(fn (): array => ClusterAgent::query()
                    ->active()
                    ->orderBy('name')
                    ->pluck('name', 'id')
                    ->all())
                ->searchable()
                ->preload()
                ->live()
                ->required(),
            Select::make('tools')
                ->label('Security Tools')
                ->multiple()
                ->options(function (Get $get): array {
                    $agent = ClusterAgent::query()->find($get('cluster_agent_id'));
                    $supportedTools = TaskExecutionService::getAvailableTools();

                    if (! $agent) {
                        return $supportedTools;
                    }

                    $agentTools = collect($agent->available_tools)
                        ->map(function (mixed $tool): ?string {
                            if (! is_scalar($tool)) {
                                return null;
                            }

                            return match (strtolower(str_replace('_', '-', trim((string) $tool)))) {
                                'kube-bench', 'kubebench' => 'kubebench',
                                'kubescape', 'kube-escape' => 'kubescape',
                                'rbac-tool', 'rbac_tool', 'rbac' => 'rbac-tool',
                                'nmap', 'n-map' => 'nmap',
                                'checkov', 'check-ov' => 'checkov',
                                default => strtolower(str_replace('_', '-', trim((string) $tool))),
                            };
                        })
                        ->filter(fn (string $tool): bool => array_key_exists($tool, $supportedTools))
                        ->mapWithKeys(fn (string $tool): array => [$tool => $supportedTools[$tool]])
                        ->all();

                    return $agentTools !== [] ? $agentTools : $supportedTools;
                })
                ->searchable()
                ->preload()
                ->required()
                ->helperText('Choose one or more tools that this selected agent can execute.'),
            Textarea::make('notes')
                ->rows(4)
                ->placeholder('Optional execution notes, scope, or investigation context.'),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('created_at', 'desc')
            ->columns([
                Tables\Columns\TextColumn::make('task_id')
                    ->label('Task ID')
                    ->searchable()
                    ->copyable(),
                Tables\Columns\TextColumn::make('title')
                    ->searchable()
                    ->wrap(),
                Tables\Columns\TextColumn::make('clusterAgent.name')
                    ->label('Agent')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('tools')
                    ->label('Tools')
                    ->state(fn (SecurityTask $record): array => collect($record->tools)
                        ->map(fn (string $tool): string => TaskExecutionService::getAvailableTools()[$tool] ?? $tool)
                        ->values()
                        ->all())
                    ->badge()
                    ->listWithLineBreaks(),
                Tables\Columns\TextColumn::make('status')
                    ->badge()
                    ->formatStateUsing(fn (SecurityTaskStatus $state): string => $state->getLabel())
                    ->color(fn (SecurityTaskStatus $state): string => $state->getColor()),
                Tables\Columns\TextColumn::make('progress')
                    ->label('Progress')
                    ->formatStateUsing(fn (int $state): string => $state . '%')
                    ->sortable(),
                Tables\Columns\TextColumn::make('last_message')
                    ->label('Execution Notes')
                    ->wrap()
                    ->toggleable(),
                Tables\Columns\TextColumn::make('created_at')
                    ->label('Submitted At')
                    ->dateTime('d M Y H:i')
                    ->sortable(),
            ])
            ->filters([
                Tables\Filters\SelectFilter::make('status')
                    ->options(SecurityTaskStatus::options()),
                Tables\Filters\SelectFilter::make('cluster_agent_id')
                    ->label('Cluster Agent')
                    ->options(fn (): array => ClusterAgent::query()->orderBy('name')->pluck('name', 'id')->all()),
            ])
            ->actions([
                Action::make('refresh')
                    ->label('Refresh Status')
                    ->icon('heroicon-o-arrow-path')
                    ->color('gray')
                    ->action(fn (SecurityTask $record) => app(SecurityTaskSyncService::class)->syncTask($record))
                    ->successNotificationTitle('Remote task status refreshed.'),
                Action::make('run')
                    ->label('Dispatch Task')
                    ->icon('heroicon-o-play')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->action(fn (SecurityTask $record) => app(TaskExecutionService::class)->run($record))
                    ->successNotificationTitle('Task dispatch request sent.'),
                Action::make('results')
                    ->label('See Findings')
                    ->icon('heroicon-o-eye')
                    ->color('primary')
                    ->url(fn (SecurityTask $record): string => SecurityTaskResultResource::getUrl('index') . '?task=' . urlencode($record->task_id)),
                DeleteAction::make()
                    ->label('Delete Task')
                    ->icon('heroicon-o-trash')
                    ->requiresConfirmation()
                    ->successNotificationTitle('Task deleted.'),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListSecurityTasks::route('/'),
            'create' => Pages\CreateSecurityTask::route('/create'),
        ];
    }
}
