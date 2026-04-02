<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ClusterAgentResource\Pages;
use App\Models\ClusterAgent;
use Filament\Forms\Components\TextInput;
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
                Tables\Columns\TextColumn::make('endpoint')
                    ->label('Endpoint')
                    ->searchable()
                    ->toggleable(),
                Tables\Columns\IconColumn::make('is_active')
                    ->label('Active')
                    ->boolean(),
                Tables\Columns\TextColumn::make('created_at')
                    ->label('Registered')
                    ->dateTime('d M Y H:i')
                    ->sortable(),
            ])
            ->filters([
                Tables\Filters\TernaryFilter::make('is_active')
                    ->label('Agent Status'),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListClusterAgents::route('/'),
        ];
    }
}
