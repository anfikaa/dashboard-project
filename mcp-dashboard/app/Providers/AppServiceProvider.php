<?php

namespace App\Providers;

use App\Support\AwsCredentialFactory;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if (AwsCredentialFactory::debugEnabled()) {
            Log::info('AWS credential resolution initialized.', AwsCredentialFactory::debugContext());
        }
    }
}
