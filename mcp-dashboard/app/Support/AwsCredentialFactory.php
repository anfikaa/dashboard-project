<?php

namespace App\Support;

use Aws\Credentials\CredentialProvider;
use Aws\Credentials\EcsCredentialProvider;

class AwsCredentialFactory
{
    protected const ECS_CONTAINER_METADATA_HOST = 'http://169.254.170.2';

    public static function debugEnabled(): bool
    {
        return filter_var(env('AWS_CREDENTIAL_DEBUG', false), FILTER_VALIDATE_BOOL);
    }

    public static function usingInjectedContainerCredentials(): bool
    {
        return self::containerCredentialsUri() !== null;
    }

    public static function sharedProfile(): ?string
    {
        if (self::usingInjectedContainerCredentials()) {
            return null;
        }

        $profile = env('AWS_PROFILE');

        return is_string($profile) && $profile !== '' ? $profile : null;
    }

    public static function provider(): callable
    {
        $provider = self::usingInjectedContainerCredentials()
            ? self::makeContainerCredentialProvider()
            : CredentialProvider::defaultProvider();

        return CredentialProvider::memoize($provider);
    }

    public static function applyToConfig(array $config): array
    {
        $config['credentials'] = self::provider();
        $config['ec2_metadata_v1_disabled'] = true;

        return $config;
    }

    public static function disableInstanceMetadataWhenNeeded(): void
    {
        if (self::usingInjectedContainerCredentials()) {
            putenv('AWS_EC2_METADATA_DISABLED=true');
            $_ENV['AWS_EC2_METADATA_DISABLED'] = 'true';
            $_SERVER['AWS_EC2_METADATA_DISABLED'] = 'true';
        }
    }

    public static function debugContext(): array
    {
        return [
            'aws_credential_mode' => self::usingInjectedContainerCredentials() ? 'container' : 'default-chain',
            'aws_credential_provider_method' => self::usingInjectedContainerCredentials() ? 'EcsCredentialProvider' : 'defaultProvider',
            'aws_container_credentials_uri_present' => self::containerCredentialsUri() !== null,
            'aws_container_authorization_token_present' => self::hasAuthorizationToken(),
            'aws_profile_active' => self::sharedProfile(),
            'aws_region' => env('AWS_DEFAULT_REGION'),
            'aws_dynamodb_region' => env('AWS_DYNAMODB_REGION'),
            'aws_endpoint' => env('AWS_ENDPOINT'),
            'aws_dynamodb_endpoint' => env('AWS_DYNAMODB_ENDPOINT'),
        ];
    }

    protected static function makeContainerCredentialProvider(): callable
    {
        return new EcsCredentialProvider(self::ecsProviderConfig());
    }

    protected static function hasAuthorizationToken(): bool
    {
        $authorization = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN');

        if (is_string($authorization) && $authorization !== '') {
            return true;
        }

        $tokenFile = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');

        return is_string($tokenFile) && $tokenFile !== '' && is_readable($tokenFile);
    }

    protected static function ecsProviderConfig(): array
    {
        return [
            'timeout' => max(1, (int) env('AWS_CONTAINER_CREDENTIALS_TIMEOUT', 5)),
            'retries' => max(0, (int) env('AWS_METADATA_SERVICE_NUM_ATTEMPTS', 1)),
        ];
    }

    protected static function containerCredentialsUri(): ?string
    {
        $fullUri = getenv('AWS_CONTAINER_CREDENTIALS_FULL_URI');

        if (is_string($fullUri) && $fullUri !== '') {
            return $fullUri;
        }

        $relativeUri = getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');

        if (is_string($relativeUri) && $relativeUri !== '') {
            return rtrim(self::ECS_CONTAINER_METADATA_HOST, '/') . '/' . ltrim($relativeUri, '/');
        }

        return null;
    }
}
