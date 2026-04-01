<?php

namespace App\Filament\Resources\SecurityTaskResultResource\Pages;

use App\Filament\Resources\SecurityTaskResultResource;
use Filament\Resources\Pages\ListRecords;
use Illuminate\Contracts\Support\Htmlable;

class ListSecurityTaskResults extends ListRecords
{
    protected static string $resource = SecurityTaskResultResource::class;

    public function getSubheading(): string | Htmlable | null
    {
        if (! request()->query('task')) {
            return 'Review all task findings or narrow the table using the built-in task and time filters.';
        }

        return 'Showing findings for task ' . request()->query('task') . '.';
    }
}
