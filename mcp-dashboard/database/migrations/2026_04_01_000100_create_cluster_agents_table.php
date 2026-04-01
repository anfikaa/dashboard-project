<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cluster_agents', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('cluster_name');
            $table->string('endpoint')->nullable();
            $table->json('available_tools');
            $table->boolean('is_active')->default(true);
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cluster_agents');
    }
};
