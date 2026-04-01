<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityTaskResult extends Model
{
    protected $fillable = [
        'security_task_id',
        'task_identifier',
        'source_tool',
        'severity',
        'scan_finding',
        'recommendation',
        'suggestion',
        'metadata',
        'scanned_at',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'scanned_at' => 'datetime',
        ];
    }

    public function task(): BelongsTo
    {
        return $this->belongsTo(SecurityTask::class, 'security_task_id');
    }
}
