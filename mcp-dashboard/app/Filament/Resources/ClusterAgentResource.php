<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ClusterAgentResource\Pages;
use App\Models\ClusterAgent;
use App\Services\TaskExecutionService;
use Filament\Actions\EditAction;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;

class ClusterAgentResource extends Resource
{
    protected static ?string $model = ClusterAgent::class;

    protected static string | \BackedEnum | null $navigationIcon = 'heroicon-o-server-stack';

    protected static \UnitEnum | string | null $navigationGroup = 'Security Operations';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([
            TextInput::make('name')
                ->required()
                ->maxLength(255),
            TextInput::make('cluster_name')
                ->required()
                ->maxLength(255),
            TextInput::make('endpoint')
                ->label('API / Agent Endpoint')
                ->url()
                ->maxLength(255),
            CheckboxList::make('available_tools')
                ->label('Available Security Tools')
                ->options(TaskExecutionService::getAvailableTools())
                ->columns(2)
                ->required(),
            Toggle::make('is_active')
                ->label('Agent Active')
                ->default(true),
            DateTimePicker::make('last_seen_at')
                ->label('Last Seen At'),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('name')
            ->columns([
                Tables\Columns\TextColumn::make('name')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('cluster_name')
                    ->label('Cluster')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('available_tools')
                    ->label('Tools')
                    ->state(fn (ClusterAgent $record): array => collect($record->available_tools)
                        ->map(fn (string $tool): string => TaskExecutionService::getAvailableTools()[$tool] ?? $tool)
                        ->values()
                        ->all())
                    ->badge()
                    ->listWithLineBreaks(),
                Tables\Columns\IconColumn::make('is_active')
                    ->label('Active')
                    ->boolean(),
                Tables\Columns\TextColumn::make('last_seen_at')
                    ->label('Last Seen')
                    ->dateTime('d M Y H:i')
                    ->sortable(),
            ])
            ->filters([
                Tables\Filters\TernaryFilter::make('is_active')
                    ->label('Agent Status'),
            ])
            ->actions([
                EditAction::make(),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListClusterAgents::route('/'),
            'create' => Pages\CreateClusterAgent::route('/create'),
            'edit' => Pages\EditClusterAgent::route('/{record}/edit'),
        ];
    }
}
