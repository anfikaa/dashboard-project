<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('cluster_agents', function (Blueprint $table): void {
            $table->string('label')->nullable()->after('name');
            $table->string('provider')->nullable()->after('cluster_name');
            $table->string('region')->nullable()->after('provider');
            $table->string('status')->nullable()->after('region');
        });
    }

    public function down(): void
    {
        Schema::table('cluster_agents', function (Blueprint $table): void {
            $table->dropColumn(['label', 'provider', 'region', 'status']);
        });
    }
};
