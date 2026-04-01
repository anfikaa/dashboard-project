<?php

namespace App\Enums;

enum SecurityTaskStatus: string
{
    case Pending = 'pending';
    case Running = 'running';
    case Completed = 'completed';
    case Failed = 'failed';

    public function getLabel(): string
    {
        return match ($this) {
            self::Pending => 'Pending',
            self::Running => 'Running',
            self::Completed => 'Completed',
            self::Failed => 'Failed',
        };
    }

    public function getColor(): string
    {
        return match ($this) {
            self::Pending => 'gray',
            self::Running => 'warning',
            self::Completed => 'success',
            self::Failed => 'danger',
        };
    }

    public static function options(): array
    {
        return collect(self::cases())
            ->mapWithKeys(fn (self $status): array => [$status->value => $status->getLabel()])
            ->all();
    }
}
