<?php

namespace App\Models;

use App\Enums\SecurityTaskStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Str;

class SecurityTask extends Model
{
    protected $fillable = [
        'task_id',
        'title',
        'cluster_agent_id',
        'tools',
        'status',
        'progress',
        'notes',
        'summary',
        'last_message',
        'submitted_by',
        'started_at',
        'completed_at',
    ];

    protected function casts(): array
    {
        return [
            'tools' => 'array',
            'summary' => 'array',
            'progress' => 'integer',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
            'status' => SecurityTaskStatus::class,
        ];
    }

    protected static function booted(): void
    {
        static::creating(function (self $task): void {
            if (blank($task->task_id)) {
                $task->task_id = 'TASK-' . now()->format('YmdHis') . '-' . Str::upper(Str::random(4));
            }

            $task->status ??= SecurityTaskStatus::Pending;
            $task->progress ??= 0;
        });
    }

    public function clusterAgent(): BelongsTo
    {
        return $this->belongsTo(ClusterAgent::class);
    }

    public function results(): HasMany
    {
        return $this->hasMany(SecurityTaskResult::class);
    }

    public function submitter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'submitted_by');
    }
}
