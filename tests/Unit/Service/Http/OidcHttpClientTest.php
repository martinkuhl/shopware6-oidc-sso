<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Http;

use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Locks in the client-authentication behavior that fixes token-exchange
 * failures against IdPs (Authelia, Keycloak, ...) whose default
 * `token_endpoint_auth_method` is `client_secret_basic` — see
 * TokenExchangeService for the confidential-client-vs-public-client rules.
 */
#[CoversClass(OidcHttpClient::class)]
final class OidcHttpClientTest extends TestCase
{
    public function testPostFormSendsNoAuthorizationHeaderWithoutBasicAuthCredentials(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getContent')->willReturn('{}');
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient->expects(self::once())
            ->method('request')
            ->with('POST', 'https://idp.example/token', self::callback(
                static fn (array $options): bool => !isset($options['headers']['Authorization']),
            ))
            ->willReturn($response);

        $client = new OidcHttpClient($httpClient, $this->createMock(LoggerInterface::class));

        $client->postForm('https://idp.example/token', ['client_id' => 'public-client'], 10);
    }

    public function testPostFormSendsABasicAuthorizationHeaderWithCredentials(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getContent')->willReturn('{}');
        $response->method('getStatusCode')->willReturn(200);

        $expectedHeader = 'Basic ' . base64_encode('my-client:my-secret');

        $httpClient = $this->createMock(HttpClientInterface::class);
        $httpClient->expects(self::once())
            ->method('request')
            ->with('POST', 'https://idp.example/token', self::callback(
                static fn (array $options): bool => ($options['headers']['Authorization'] ?? null) === $expectedHeader,
            ))
            ->willReturn($response);

        $client = new OidcHttpClient($httpClient, $this->createMock(LoggerInterface::class));

        $client->postForm('https://idp.example/token', [], 10, 'my-client', 'my-secret');
    }

    public function testPostIgnoringResponseBodyAcceptsAnEmptySuccessBody(): void
    {
        // RFC 7009 §2.2: a successful revocation answers 200, content ignored (Authelia: empty).
        $httpClient = new MockHttpClient(new MockResponse(''));

        (new OidcHttpClient($httpClient, new NullLogger()))->postFormIgnoringResponseBody('https://idp.example/revoke', ['token' => 't'], 5, 'my-client', 'my-secret');

        self::assertSame(1, $httpClient->getRequestsCount());
    }

    public function testPostIgnoringResponseBodyStillFailsOnAnErrorStatus(): void
    {
        $httpClient = new MockHttpClient(new MockResponse('{"error":"invalid_client"}', ['http_code' => 401]));

        $this->expectException(OidcHttpException::class);
        $this->expectExceptionMessage('failed with status 401');

        (new OidcHttpClient($httpClient, new NullLogger()))->postFormIgnoringResponseBody('https://idp.example/revoke', ['token' => 't'], 5);
    }

    public function testGetIsRetriedOnceAfterATransportError(): void
    {
        $calls = 0;
        $httpClient = new MockHttpClient(static function () use (&$calls): MockResponse {
            ++$calls;

            if ($calls === 1) {
                throw new TransportException('Connection reset');
            }

            return new MockResponse('{"issuer":"x"}');
        });

        $result = (new OidcHttpClient($httpClient, new NullLogger()))->getJson('https://idp.example/.well-known/openid-configuration', 5);

        self::assertSame(['issuer' => 'x'], $result);
        self::assertSame(2, $calls);
    }

    public function testPostIsNeverRetried(): void
    {
        $calls = 0;
        $httpClient = new MockHttpClient(static function () use (&$calls): MockResponse {
            ++$calls;

            throw new TransportException('Connection reset');
        });

        try {
            (new OidcHttpClient($httpClient, new NullLogger()))->postForm('https://idp.example/token', ['code' => 'single-use'], 5);
            self::fail('Expected an OidcHttpException.');
        } catch (OidcHttpException) {
            self::assertSame(1, $calls, 'a retry would replay the single-use authorization code');
        }
    }

    public function testBlockedAddressIsNotRetriedAndTheMessageHasNoQuery(): void
    {
        $calls = 0;
        $httpClient = new MockHttpClient(static function () use (&$calls): MockResponse {
            ++$calls;

            throw new TransportException('Host "10.0.0.1" is blocked for "https://idp.example/jwks?token=abc".');
        });

        try {
            (new OidcHttpClient($httpClient, new NullLogger()))->getJson('https://idp.example/jwks?token=abc', 5);
            self::fail('Expected an OidcHttpException.');
        } catch (OidcHttpException $exception) {
            self::assertSame(1, $calls);
            self::assertStringNotContainsString('token=abc', $exception->getMessage());
        }
    }
}
