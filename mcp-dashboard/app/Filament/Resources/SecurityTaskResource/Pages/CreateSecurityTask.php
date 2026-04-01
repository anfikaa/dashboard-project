<?php

namespace App\Filament\Resources\SecurityTaskResource\Pages;

use App\Filament\Resources\SecurityTaskResource;
use App\Services\TaskExecutionService;
use Filament\Resources\Pages\CreateRecord;

class CreateSecurityTask extends CreateRecord
{
    protected static string $resource = SecurityTaskResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $data['submitted_by'] = auth()->id();

        return $data;
    }

    protected function afterCreate(): void
    {
        app(TaskExecutionService::class)->run($this->record);
    }

    protected function getRedirectUrl(): string
    {
        return static::getResource()::getUrl('index');
    }

    protected function getCreatedNotificationTitle(): ?string
    {
        return 'Task submitted and executed.';
    }
}
