<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ClusterAgent extends Model
{
    protected $fillable = [
        'name',
        'label',
        'cluster_name',
        'provider',
        'region',
        'status',
        'endpoint',
        'available_tools',
        'is_active',
        'last_seen_at',
    ];

    protected function casts(): array
    {
        return [
            'available_tools' => 'array',
            'is_active' => 'boolean',
            'last_seen_at' => 'datetime',
        ];
    }

    public function tasks(): HasMany
    {
        return $this->hasMany(SecurityTask::class);
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    public function scopeRemoteBacked(Builder $query): Builder
    {
        return $query->whereNotNull('label');
    }
}
