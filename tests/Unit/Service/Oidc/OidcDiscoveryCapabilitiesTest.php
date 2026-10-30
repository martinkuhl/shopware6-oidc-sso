<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcDiscoveryService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OidcDiscoveryService::class)]
final class OidcDiscoveryCapabilitiesTest extends TestCase
{
    public function testDiscoveryReportsTheAdvertisedMethods(): void
    {
        $http = $this->createStub(OidcHttpClient::class);
        $http->method('getJson')->willReturn([
            'issuer' => 'https://idp.example',
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 7],
            'code_challenge_methods_supported' => ['S256'],
            'claims_parameter_supported' => true,
        ]);

        $result = (new OidcDiscoveryService($http))->discover('https://idp.example/.well-known/openid-configuration');

        self::assertSame(['client_secret_post'], $result['tokenEndpointAuthMethodsSupported'] ?? null);
        self::assertSame(['S256'], $result['codeChallengeMethodsSupported'] ?? null);
        self::assertTrue($result['claimsParameterSupported']);
        self::assertArrayNotHasKey('revocationEndpointAuthMethodsSupported', $result);
    }

    public function testAMismatchedIssuerIsAnErrorAndUnadvertisedMethodsAreWarnings(): void
    {
        $discovered = [
            'issuer' => 'https://idp.example/',
            'tokenEndpointAuthMethodsSupported' => ['client_secret_post'],
            'codeChallengeMethodsSupported' => ['S256', 'plain'],
        ];

        $result = OidcDiscoveryService::capabilityMismatches($discovered, [
            'issuer' => 'https://idp.example',
            'tokenEndpointAuthMethod' => 'client_secret_basic',
            'revocationEndpointAuthMethod' => 'client_secret_basic',
            'pkceFlow' => 'plain',
        ]);

        self::assertCount(1, $result['errors'], 'trailing slash: every ID token would be refused');
        self::assertCount(2, $result['warnings'], 'Basic not advertised, plain while S256 is');

        self::assertSame(['errors' => [], 'warnings' => []], OidcDiscoveryService::capabilityMismatches($discovered, [
            'issuer' => 'https://idp.example/',
            'tokenEndpointAuthMethod' => 'client_secret_post',
            'pkceFlow' => 'S256',
        ]));
    }
}
