<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Oidc\ClientAuthentication;
use MartinKuhl\Sw6Oidc\Service\Oidc\TokenExchangeService;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\ClientSecretUnavailableException;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Regression coverage for the Authelia/Keycloak-compatible client
 * authentication fix: a confidential client must authenticate via HTTP Basic
 * (RFC 6749 §2.3.1) with client_id/client_secret omitted from the body,
 * mirroring the Magento sibling module's tested AccessTokenRequestBody
 * behavior ("client_id present in the token-exchange body iff no Basic-auth
 * header is sent"); a public client has no secret, so it identifies itself
 * via client_id in the body instead, with no Authorization header.
 */
#[CoversClass(TokenExchangeService::class)]
#[CoversClass(ClientAuthentication::class)]
final class TokenExchangeServiceTest extends TestCase
{
    public function testConfidentialClientAuthenticatesViaBasicAuthAndOmitsCredentialsFromTheBody(): void
    {
        $provider = $this->buildProvider(publicClient: false);

        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->expects(self::once())
            ->method('postForm')
            ->with(
                'https://idp.example/token',
                self::callback(static function (array $params): bool {
                    self::assertArrayNotHasKey('client_id', $params);
                    self::assertArrayNotHasKey('client_secret', $params);
                    self::assertSame('authorization_code', $params['grant_type']);
                    self::assertSame('the-code', $params['code']);

                    return true;
                }),
                10,
                'client-1',
                'the-secret',
            )
            ->willReturn(['access_token' => 'at']);

        $service = new TokenExchangeService($httpClient);
        $service->exchangeCodeForTokens($provider, 'the-code', 'https://shop.example/callback', 'verifier');
    }

    public function testClientSecretPostSendsTheCredentialsInTheBodyWithoutAnAuthorizationHeader(): void
    {
        $provider = $this->buildProvider(publicClient: false);
        $provider->setTokenEndpointAuthMethod(Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_POST);

        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->expects(self::once())
            ->method('postForm')
            ->with(
                'https://idp.example/token',
                self::callback(static function (array $params): bool {
                    self::assertSame('client-1', $params['client_id']);
                    self::assertSame('the-secret', $params['client_secret']);
                    self::assertSame('the-code', $params['code']);

                    return true;
                }),
                10,
                null,
                null,
            )
            ->willReturn(['access_token' => 'at']);

        (new TokenExchangeService($httpClient))->exchangeCodeForTokens($provider, 'the-code', 'https://shop.example/callback', 'verifier');
    }

    public function testPublicClientIgnoresClientSecretPost(): void
    {
        $provider = $this->buildProvider(publicClient: true);
        $provider->setTokenEndpointAuthMethod(Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_POST);

        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->expects(self::once())
            ->method('postForm')
            ->with(
                'https://idp.example/token',
                self::callback(static function (array $params): bool {
                    self::assertSame('client-1', $params['client_id']);
                    self::assertArrayNotHasKey('client_secret', $params);

                    return true;
                }),
                10,
                null,
                null,
            )
            ->willReturn(['access_token' => 'at']);

        (new TokenExchangeService($httpClient))->exchangeCodeForTokens($provider, 'the-code', 'https://shop.example/callback', 'verifier');
    }

    public function testPublicClientSendsClientIdInTheBodyWithoutAnAuthorizationHeader(): void
    {
        $provider = $this->buildProvider(publicClient: true);

        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->expects(self::once())
            ->method('postForm')
            ->with(
                'https://idp.example/token',
                self::callback(static function (array $params): bool {
                    self::assertSame('client-1', $params['client_id']);
                    self::assertArrayNotHasKey('client_secret', $params);

                    return true;
                }),
                10,
                null,
                null,
            )
            ->willReturn(['access_token' => 'at']);

        $service = new TokenExchangeService($httpClient);
        $service->exchangeCodeForTokens($provider, 'the-code', 'https://shop.example/callback', 'verifier');
    }

    public function testUndecryptableSecretFailsBeforeAnyRequest(): void
    {
        $provider = $this->buildProvider(publicClient: false);
        $provider->setClientSecret((new Sw6OidcEncryptor('rotated-away'))->encrypt('the-secret'));

        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->expects(self::never())->method('postForm');

        $this->expectException(ClientSecretUnavailableException::class);
        (new TokenExchangeService($httpClient))->exchangeCodeForTokens($provider, 'the-code', 'https://shop.example/callback', 'verifier');
    }

    private function buildProvider(bool $publicClient): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('provider-1');
        $provider->setAppName('test-provider');
        $provider->setClientId('client-1');
        $provider->setClientSecret('the-secret');
        $provider->setAccessTokenEndpoint('https://idp.example/token');
        $provider->setPublicClient($publicClient);
        $provider->setHttpTimeout(10);

        return $provider;
    }
}
