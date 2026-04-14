<?php

namespace App\Filament\Resources\SecurityTaskResource\Pages;

use App\Filament\Resources\SecurityTaskResource;
use App\Services\SecurityTaskSyncService;
use Filament\Actions\Action;
use Filament\Actions\CreateAction;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;
use Throwable;

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
                    try {
                        $count = app(SecurityTaskSyncService::class)->syncRecentTasks();

                        Notification::make()
                            ->title('Remote task status refreshed.')
                            ->body("Synced {$count} recent task(s).")
                            ->success()
                            ->send();
                    } catch (Throwable $exception) {
                        report($exception);

                        Notification::make()
                            ->title('Remote status refresh failed.')
                            ->body('Check the application logs for the sync error details.')
                            ->danger()
                            ->send();
                    }
                })
                ->requiresConfirmation(false),
            CreateAction::make()
                ->label('Submit Task'),
        ];
    }
}
