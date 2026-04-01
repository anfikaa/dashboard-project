<?php

namespace App\Filament\Resources\ClusterAgentResource\Pages;

use App\Filament\Resources\ClusterAgentResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListClusterAgents extends ListRecords
{
    protected static string $resource = ClusterAgentResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make(),
        ];
    }
}
