<?php

namespace App\Filament\Resources\SecurityTaskResource\Pages;

use App\Filament\Resources\SecurityTaskResource;
use App\Models\ClusterAgent;
use App\Models\SecurityTask;
use App\Services\TaskExecutionService;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\ValidationException;
use Filament\Resources\Pages\CreateRecord;

class CreateSecurityTask extends CreateRecord
{
    protected static string $resource = SecurityTaskResource::class;

    /** @var array<int, SecurityTask> */
    protected array $createdRecords = [];

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $data['submitted_by'] = auth()->id();
        $data['tools'] = array_values(array_filter([
            is_array($data['tools'] ?? null) ? ($data['tools'][0] ?? null) : ($data['tools'] ?? null),
        ]));

        return $data;
    }

    protected function handleRecordCreation(array $data): Model
    {
        if (($data['cluster_agent_id'] ?? null) !== 'all') {
            /** @var SecurityTask $record */
            $record = static::getModel()::create($data);
            $this->createdRecords = [$record];

            return $record;
        }

        $agents = ClusterAgent::query()
            ->remoteBacked()
            ->active()
            ->orderBy('name')
            ->get();

        if ($agents->isEmpty()) {
            throw ValidationException::withMessages([
                'data.cluster_agent_id' => 'No active clusters are available for the `All` option.',
            ]);
        }

        $recordData = $data;
        $recordData['cluster_agent_id'] = $agents->first()->getKey();
        $recordData['summary'] = array_merge(
            is_array($recordData['summary'] ?? null) ? $recordData['summary'] : [],
            ['cluster_scope' => 'all'],
        );

        /** @var SecurityTask $record */
        $record = static::getModel()::create($recordData);
        $this->createdRecords = [$record];

        return $record;
    }

    protected function afterCreate(): void
    {
        $service = app(TaskExecutionService::class);

        foreach ($this->createdRecords !== [] ? $this->createdRecords : [$this->record] as $record) {
            $service->run($record);
        }
    }

    protected function getRedirectUrl(): string
    {
        return static::getResource()::getUrl('index');
    }

    protected function getCreatedNotificationTitle(): ?string
    {
        $scope = data_get($this->createdRecords[0] ?? null, 'summary.cluster_scope');

        return $scope === 'all'
            ? 'Task submitted and dispatched to all active clusters.'
            : 'Task submitted and dispatched.';
    }
}
