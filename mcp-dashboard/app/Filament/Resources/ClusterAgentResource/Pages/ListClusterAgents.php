<?php

namespace App\Filament\Resources\ClusterAgentResource\Pages;

use App\Filament\Resources\ClusterAgentResource;
use App\Services\DynamoDbClusterAgentService;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;
use Throwable;

class ListClusterAgents extends ListRecords
{
    protected static string $resource = ClusterAgentResource::class;

    public function mount(): void
    {
        parent::mount();

        $this->syncAgentsFromRegistry(true, notifyOnFailure: true);
    }

    public function hydrate(): void
    {
        $this->syncAgentsFromRegistry();
    }

    protected function syncAgentsFromRegistry(bool $forceRefresh = false, bool $notifyOnFailure = false): void
    {
        try {
            app(DynamoDbClusterAgentService::class)->syncToDatabase($forceRefresh);
        } catch (Throwable $exception) {
            report($exception);

            if (! $notifyOnFailure) {
                return;
            }

            Notification::make()
                ->title('Unable to sync cluster agents from DynamoDB.')
                ->body('The page is showing the latest cached data that is available.')
                ->danger()
                ->send();
        }
    }
}
