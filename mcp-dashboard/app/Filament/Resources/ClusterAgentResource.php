<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ClusterAgentResource\Pages;
use App\Models\ClusterAgent;
use App\Services\DynamoDbClusterAgentService;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Throwable;

class ClusterAgentResource extends Resource
{
    protected static ?string $model = ClusterAgent::class;

    protected static string | \BackedEnum | null $navigationIcon = 'heroicon-o-server-stack';

    protected static \UnitEnum | string | null $navigationGroup = 'Security Operations';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function getEloquentQuery(): Builder
    {
        return parent::getEloquentQuery()
            ->remoteBacked();
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('cluster_name')
            ->poll('15s')
            ->headerActions([
                Action::make('syncAgents')
                    ->label('Sync Agents')
                    ->icon('heroicon-o-arrow-path')
                    ->action(function (): void {
                        try {
                            $count = app(DynamoDbClusterAgentService::class)->syncToDatabase(true);

                            Notification::make()
                                ->title('Cluster agents synced.')
                                ->body(sprintf('%d agent(s) loaded from DynamoDB.', $count))
                                ->success()
                                ->send();
                        } catch (Throwable $exception) {
                            report($exception);

                            Notification::make()
                                ->title('Unable to sync cluster agents from DynamoDB.')
                                ->body('Please check the DynamoDB access policy or AWS credentials for this app.')
                                ->danger()
                                ->send();
                        }
                    })
            ])
            ->columns([
                Tables\Columns\TextColumn::make('cluster_name')
                    ->label('Cluster Agent')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('label')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('provider')
                    ->badge()
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('region')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('status')
                    ->badge()
                    ->color(fn (?string $state): string => match (strtolower((string) $state)) {
                        'healthy', 'active', 'running', 'online' => 'success',
                        'warning', 'degraded' => 'warning',
                        'failed', 'unhealthy', 'offline', 'error' => 'danger',
                        default => 'gray',
                    })
                    ->formatStateUsing(fn (?string $state): string => $state ?: 'unknown')
                    ->searchable()
                    ->sortable(),
                Tables\Columns\TextColumn::make('available_tools')
                    ->label('Tools')
                    ->badge()
                    ->separator(',')
                    ->wrap(),
                Tables\Columns\TextColumn::make('last_seen_at')
                    ->label('Synced')
                    ->dateTime('d M Y H:i')
                    ->timezone('Asia/Jakarta')
                    ->placeholder('-')
                    ->sortable(),
            ])
            ->filters([]);
    }

    public static function getPages(): array
    {
        return [
            'index' => Pages\ListClusterAgents::route('/'),
        ];
    }
}
