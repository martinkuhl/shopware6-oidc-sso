<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Health;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderConfigInspector;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ProviderConfigInspector::class)]
final class ProviderConfigInspectorTest extends TestCase
{
    public function testCompleteProviderHasNoProblems(): void
    {
        self::assertSame([], $this->inspector()->problems($this->provider([])));
    }

    public function testReportsMissingFieldsAndUnusableSecrets(): void
    {
        self::assertSame(['jwks_endpoint_missing', 'issuer_missing'], $this->inspector()->problems($this->provider(['jwksEndpoint' => null, 'issuer' => ' '])));
        self::assertSame(['client_secret_missing'], $this->inspector()->problems($this->provider(['clientSecret' => ''])));

        $foreignEnvelope = (new Sw6OidcEncryptor('other-secret'))->encrypt('s3cret', 'sw6oidc_provider.client_secret');
        self::assertSame(['client_secret_undecryptable'], $this->inspector()->problems($this->provider(['clientSecret' => $foreignEnvelope])));
    }

    public function testPublicClientsNeedNoSecret(): void
    {
        self::assertSame([], $this->inspector()->problems($this->provider(['publicClient' => true, 'clientSecret' => ''])));
    }

    private function inspector(): ProviderConfigInspector
    {
        return new ProviderConfigInspector();
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function provider(array $overrides): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign(array_merge([
            'id' => 'p1',
            'authorizeEndpoint' => 'https://idp.example/authorize',
            'accessTokenEndpoint' => 'https://idp.example/token',
            'jwksEndpoint' => 'https://idp.example/jwks',
            'issuer' => 'https://idp.example',
            'clientId' => 'shop',
            'clientSecret' => 'decrypted-secret',
            'publicClient' => false,
        ], $overrides));

        return $provider;
    }
}
