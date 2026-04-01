<?php

namespace App\Filament\Resources\SecurityTaskResource\Pages;

use App\Filament\Resources\SecurityTaskResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListSecurityTasks extends ListRecords
{
    protected static string $resource = SecurityTaskResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make()
                ->label('Submit Task'),
        ];
    }
}
