<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_task_results', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_task_id')->constrained()->cascadeOnDelete();
            $table->string('task_identifier')->index();
            $table->string('source_tool')->nullable();
            $table->string('severity', 16)->default('WARN');
            $table->text('scan_finding');
            $table->text('recommendation')->nullable();
            $table->text('suggestion')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('scanned_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_task_results');
    }
};
