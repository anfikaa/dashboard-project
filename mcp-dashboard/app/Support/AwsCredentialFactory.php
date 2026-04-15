<?php

namespace App\Support;

use Aws\Credentials\CredentialProvider;

class AwsCredentialFactory
{
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
            ? CredentialProvider::containerCredentials(self::containerProviderConfig())
            : CredentialProvider::defaultProvider();

        return CredentialProvider::memoize($provider);
    }

    public static function applyToConfig(array $config): array
    {
        $config['credentials'] = self::provider();

        return $config;
    }

    public static function debugContext(): array
    {
        return [
            'aws_credential_mode' => self::usingInjectedContainerCredentials() ? 'container' : 'default-chain',
            'aws_container_credentials_uri_present' => self::containerCredentialsUri() !== null,
            'aws_container_authorization_token_present' => self::hasAuthorizationToken(),
            'aws_profile_active' => self::sharedProfile(),
            'aws_region' => env('AWS_DEFAULT_REGION'),
            'aws_dynamodb_region' => env('AWS_DYNAMODB_REGION'),
            'aws_endpoint' => env('AWS_ENDPOINT'),
            'aws_dynamodb_endpoint' => env('AWS_DYNAMODB_ENDPOINT'),
        ];
    }

    protected static function containerProviderConfig(): array
    {
        $config = [];
        $uri = self::containerCredentialsUri();

        if ($uri !== null) {
            $config['uri'] = $uri;
        }

        $authorization = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN');

        if (is_string($authorization) && $authorization !== '') {
            $config['authorization'] = $authorization;
        } else {
            $tokenFile = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');

            if (is_string($tokenFile) && $tokenFile !== '' && is_readable($tokenFile)) {
                $token = trim((string) file_get_contents($tokenFile));

                if ($token !== '') {
                    $config['authorization'] = $token;
                }
            }
        }

        $config['timeout'] = max(1, (int) env('AWS_CONTAINER_CREDENTIALS_TIMEOUT', 5));

        return $config;
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

    protected static function containerCredentialsUri(): ?string
    {
        foreach (['AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'] as $key) {
            $value = getenv($key);

            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }
}
