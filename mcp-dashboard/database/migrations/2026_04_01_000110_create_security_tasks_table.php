<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_tasks', function (Blueprint $table): void {
            $table->id();
            $table->string('task_id')->unique();
            $table->string('title');
            $table->foreignId('cluster_agent_id')->constrained()->cascadeOnDelete();
            $table->json('tools');
            $table->string('status')->default('pending');
            $table->unsignedInteger('progress')->default(0);
            $table->text('notes')->nullable();
            $table->json('summary')->nullable();
            $table->text('last_message')->nullable();
            $table->foreignId('submitted_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_tasks');
    }
};
