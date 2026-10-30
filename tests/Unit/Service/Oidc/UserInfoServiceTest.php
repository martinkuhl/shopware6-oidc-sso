<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Oidc\UserInfoService;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\JwtTestSigner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Signed userinfo (OIDC Core §5.3.2) is verified like an ID token; JSON
 * userinfo keeps working.
 */
#[CoversClass(UserInfoService::class)]
#[CoversClass(OidcHttpClient::class)]
final class UserInfoServiceTest extends TestCase
{
    public function testJsonAndSignedUserinfoBothYieldClaims(): void
    {
        $signer = new JwtTestSigner();

        self::assertSame(['sub' => 'u1'], $this->service($signer, new MockResponse('{"sub":"u1"}', ['response_headers' => ['content-type' => 'application/json']]))->fetchClaims($this->provider(), 'at'));

        $jwt = $signer->sign(['sub' => 'u1', 'iss' => 'https://idp.example', 'aud' => 'shop', 'email' => 'a@example.com']);
        $claims = $this->service($signer, new MockResponse($jwt, ['response_headers' => ['content-type' => 'application/jwt']]))->fetchClaims($this->provider(), 'at');

        self::assertSame('a@example.com', $claims['email'] ?? null);
    }

    public function testSignedUserinfoForAnotherClientIsRefused(): void
    {
        $signer = new JwtTestSigner();
        $jwt = $signer->sign(['sub' => 'u1', 'iss' => 'https://idp.example', 'aud' => 'someone-else']);

        $this->expectException(InvalidJwtException::class);

        $this->service($signer, new MockResponse($jwt, ['response_headers' => ['content-type' => 'application/jwt']]))->fetchClaims($this->provider(), 'at');
    }

    private function service(JwtTestSigner $signer, MockResponse $userinfo): UserInfoService
    {
        $verifier = new JwtVerifier(new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson())), new ArrayAdapter(), new NullLogger());

        return new UserInfoService(new OidcHttpClient(new MockHttpClient($userinfo), new NullLogger()), $verifier);
    }

    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign(['id' => 'a1000000000000000000000000000001', 'clientId' => 'shop', 'issuer' => 'https://idp.example', 'userInfoEndpoint' => 'https://idp.example/userinfo', 'jwksEndpoint' => 'https://idp.example/jwks', 'jwksCacheTtl' => 60, 'httpTimeout' => 5]);

        return $provider;
    }
}
