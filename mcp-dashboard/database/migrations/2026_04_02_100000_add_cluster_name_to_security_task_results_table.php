<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_task_results', function (Blueprint $table): void {
            $table->string('cluster_name')->nullable()->after('source_tool')->index();
        });
    }

    public function down(): void
    {
        Schema::table('security_task_results', function (Blueprint $table): void {
            $table->dropColumn('cluster_name');
        });
    }
};
