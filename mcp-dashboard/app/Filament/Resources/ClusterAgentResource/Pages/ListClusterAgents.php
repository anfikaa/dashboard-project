<?php

namespace App\Filament\Resources\ClusterAgentResource\Pages;

use App\Filament\Resources\ClusterAgentResource;
use App\Services\DynamoDbClusterAgentService;
use Filament\Resources\Pages\ListRecords;

class ListClusterAgents extends ListRecords
{
    protected static string $resource = ClusterAgentResource::class;

    public function mount(): void
    {
        parent::mount();

        app(DynamoDbClusterAgentService::class)->syncToDatabase(true);
    }

    public function hydrate(): void
    {
        app(DynamoDbClusterAgentService::class)->syncToDatabase();
    }
}
