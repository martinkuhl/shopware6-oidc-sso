<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcConnectionTestService;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcDiscoveryService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OidcConnectionTestService::class)]
final class OidcConnectionTestServiceTest extends TestCase
{
    public function testFailsWhenClientIdIsMissing(): void
    {
        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->method('getJson')->willReturn(['keys' => [['kty' => 'RSA']]]);

        $service = new OidcConnectionTestService($httpClient, $this->createMock(OidcDiscoveryService::class), new SsrfUrlValidator());

        $result = $service->test([
            'clientId' => '',
            'hasClientSecret' => true,
            'authorizeEndpoint' => 'https://8.8.8.8/authorize',
            'accessTokenEndpoint' => 'https://8.8.8.8/token',
            'jwksEndpoint' => 'https://8.8.8.8/jwks',
        ]);

        self::assertSame('fail', $result['overallStatus']);
        self::assertSame('fail', $this->checkById($result, 'client_credentials_present')['status']);
    }

    public function testPassesWhenEverythingIsConfiguredCorrectly(): void
    {
        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->method('getJson')->willReturn(['keys' => [['kty' => 'RSA']]]);

        $discoveryService = $this->createMock(OidcDiscoveryService::class);
        $discoveryService->expects(self::never())->method('discover');

        $service = new OidcConnectionTestService($httpClient, $discoveryService, new SsrfUrlValidator());

        $result = $service->test([
            'clientId' => 'my-client',
            'hasClientSecret' => true,
            'publicClient' => false,
            'authorizeEndpoint' => 'https://8.8.8.8/authorize',
            'accessTokenEndpoint' => 'https://8.8.8.8/token',
            'jwksEndpoint' => 'https://8.8.8.8/jwks',
        ]);

        self::assertSame('pass', $result['overallStatus']);
    }

    public function testFailsWithAMissingRequiredEndpointAndWarnsAboutTheMissingJwks(): void
    {
        $httpClient = $this->createMock(OidcHttpClient::class);

        $service = new OidcConnectionTestService($httpClient, $this->createMock(OidcDiscoveryService::class), new SsrfUrlValidator());

        $result = $service->test([
            'clientId' => 'my-client',
            'hasClientSecret' => true,
            'authorizeEndpoint' => 'https://8.8.8.8/authorize',
            'accessTokenEndpoint' => 'https://8.8.8.8/token',
            // jwksEndpoint intentionally omitted
        ]);

        self::assertSame('fail', $result['overallStatus']);
        self::assertSame('fail', $this->checkById($result, 'required_endpoints_present')['status']);
        self::assertSame('warning', $this->checkById($result, 'jwks_reachable')['status']);
    }

    public function testPublicClientDoesNotRequireAClientSecret(): void
    {
        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->method('getJson')->willReturn(['keys' => [['kty' => 'RSA']]]);

        $service = new OidcConnectionTestService($httpClient, $this->createMock(OidcDiscoveryService::class), new SsrfUrlValidator());

        $result = $service->test([
            'clientId' => 'my-client',
            'hasClientSecret' => false,
            'publicClient' => true,
            'authorizeEndpoint' => 'https://8.8.8.8/authorize',
            'accessTokenEndpoint' => 'https://8.8.8.8/token',
            'jwksEndpoint' => 'https://8.8.8.8/jwks',
        ]);

        self::assertSame('pass', $this->checkById($result, 'client_credentials_present')['status']);
    }

    /**
     * @param array{overallStatus: string, checks: array<int, array{id: string, status: string, detail: string}>} $result
     *
     * @return array{id: string, status: string, detail: string}
     */
    private function checkById(array $result, string $id): array
    {
        foreach ($result['checks'] as $check) {
            if ($check['id'] === $id) {
                return $check;
            }
        }

        self::fail(sprintf('No check with id "%s" was found in the report.', $id));
    }
}
