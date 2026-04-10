<?php

namespace App\Filament\Resources\SecurityTaskResource\Pages;

use App\Filament\Resources\SecurityTaskResource;
use App\Services\SecurityTaskSyncService;
use Filament\Actions\Action;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListSecurityTasks extends ListRecords
{
    protected static string $resource = SecurityTaskResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('refreshRemoteTasks')
                ->label('Refresh Remote Status')
                ->icon('heroicon-o-arrow-path')
                ->action(function (): void {
                    app(SecurityTaskSyncService::class)->syncRecentTasks();
                })
                ->successNotificationTitle('Remote task status refreshed.'),
            CreateAction::make()
                ->label('Submit Task'),
        ];
    }
}
