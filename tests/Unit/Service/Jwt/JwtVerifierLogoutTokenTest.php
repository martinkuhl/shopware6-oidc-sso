<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Jwt;

use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\JwtTestSigner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[CoversClass(JwtVerifier::class)]
final class JwtVerifierLogoutTokenTest extends TestCase
{
    private const ISSUER = 'https://idp.example';
    private const AUDIENCE = 'client-1';

    private JwtTestSigner $signer;

    private JwtVerifier $verifier;

    protected function setUp(): void
    {
        $this->signer = new JwtTestSigner();
        $signer = $this->signer;
        $this->verifier = new JwtVerifier(
            new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson())),
            new ArrayAdapter(),
            new NullLogger(),
        );
    }

    public function testValidLogoutTokenReturnsClaims(): void
    {
        $claims = $this->verify(self::claims());

        self::assertSame('sid-1', $claims['sid']);
    }

    public function testSubAloneOrSidAloneIsEnough(): void
    {
        self::assertSame('user-1', $this->verify(self::claims(['sid' => null]))['sub']);
        self::assertSame('sid-1', $this->verify(self::claims(['sub' => null]))['sid']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidTokens(): iterable
    {
        yield 'no events' => [['events' => null], 'events'];
        yield 'events without the logout member' => [['events' => ['http://schemas.openid.net/event/other' => []]], 'events'];
        yield 'logout member not an object' => [['events' => [JwtVerifier::BACKCHANNEL_LOGOUT_EVENT => 'yes']], 'events'];
        yield 'nonce present (id_token substitution)' => [['nonce' => 'n'], 'nonce'];
        yield 'neither sub nor sid' => [['sub' => null, 'sid' => null], 'neither'];
        yield 'no iat' => [['iat' => null], 'iat'];
        yield 'expired' => [['exp' => -JwtVerifier::LEEWAY_SECONDS - 5], 'expired'];
        yield 'no jti' => [['jti' => null], 'jti'];
        yield 'too old' => [['iat' => -3600], 'too old'];
        yield 'wrong audience' => [['aud' => 'other-client'], 'audience'];
        yield 'wrong issuer' => [['iss' => 'https://evil.example'], 'issuer'];
    }

    /**
     * @param array<string, mixed> $overrides iat/exp as offsets from now (resolved when the test runs, not when the provider does)
     */
    #[DataProvider('invalidTokens')]
    public function testInvalidLogoutTokensAreRejected(array $overrides, string $messagePart): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($messagePart, '/') . '/i');

        foreach (['iat', 'exp'] as $timeClaim) {
            if (\is_int($overrides[$timeClaim] ?? null)) {
                $overrides[$timeClaim] += time();
            }
        }

        $this->verify(self::claims($overrides));
    }

    public function testTokenSignedByAnotherKeyIsRejected(): void
    {
        $this->expectException(InvalidJwtException::class);

        $this->verifier->verifyLogoutToken((new JwtTestSigner('other'))->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);
    }

    /**
     * R3-M1: anonymous logout tokens with a fresh random `kid` each must not
     * force one JWKS fetch each.
     */
    public function testRandomKidsCostAtMostOneRefetchPerEndpoint(): void
    {
        $signer = $this->signer;
        $client = new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson()));
        $verifier = new JwtVerifier($client, new ArrayAdapter(), new NullLogger());

        for ($i = 0; $i < 5; ++$i) {
            try {
                $verifier->verifyLogoutToken((new JwtTestSigner('random-' . $i))->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);
                self::fail('A token signed by an unknown key must be rejected.');
            } catch (InvalidJwtException) {
            }
        }

        // The initial fetch plus one rotation refetch for the whole flood.
        self::assertSame(2, $client->getRequestsCount());
    }

    public function testOversizedKidIsRejectedBeforeAnyFetch(): void
    {
        $client = new MockHttpClient(static fn (): MockResponse => new MockResponse('{}'));
        $verifier = new JwtVerifier($client, new ArrayAdapter(), new NullLogger());

        try {
            $verifier->verifyLogoutToken((new JwtTestSigner(str_repeat('k', 300)))->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);
            self::fail('An oversized kid must be rejected.');
        } catch (InvalidJwtException $exception) {
            self::assertStringContainsString('kid', $exception->getMessage());
        }

        self::assertSame(0, $client->getRequestsCount());
    }

    public function testRateLimitedCallersOnlyUseCachedKeys(): void
    {
        $signer = $this->signer;
        $client = new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson()));
        $verifier = new JwtVerifier($client, new ArrayAdapter(), new NullLogger());
        $verifier->verifyLogoutToken($this->signer->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);

        // A correctly signed token still passes from the cache ...
        $verifier->verifyLogoutToken($this->signer->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5, allowRefetch: false);

        // ... an unknown kid never triggers a fetch.
        try {
            $verifier->verifyLogoutToken((new JwtTestSigner('rotated'))->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5, allowRefetch: false);
            self::fail('An unknown key must be rejected.');
        } catch (InvalidJwtException) {
        }

        self::assertSame(1, $client->getRequestsCount());
    }

    public function testAFailingLogoutFetchDoesNotPauseLogins(): void
    {
        $cache = new ArrayAdapter();
        $failing = new JwtVerifier(new MockHttpClient(static fn (): MockResponse => new MockResponse('', ['http_code' => 503])), $cache, new NullLogger());

        try {
            $failing->verifyLogoutToken($this->signer->sign(self::claims()), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);
        } catch (InvalidJwtException) {
        }

        self::assertFalse($cache->getItem('sw6oidc_jwks_fail_login_' . hash('sha256', 'https://idp.example/jwks'))->isHit());
        self::assertTrue($cache->getItem('sw6oidc_jwks_fail_logout_' . hash('sha256', 'https://idp.example/jwks'))->isHit());
    }

    public function testDecodeUnverifiedReadsWithoutChecking(): void
    {
        $token = (new JwtTestSigner('other'))->sign(self::claims(['iss' => 'https://anything.example']));

        self::assertSame('https://anything.example', $this->verifier->decodeUnverified($token)['iss'] ?? null);
        self::assertNull($this->verifier->decodeUnverified('not-a-jwt'));
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private function verify(array $claims): array
    {
        return $this->verifier->verifyLogoutToken($this->signer->sign($claims), 'https://idp.example/jwks', self::ISSUER, self::AUDIENCE, 60, 5);
    }

    /**
     * @param array<string, mixed> $overrides null removes the claim
     *
     * @return array<string, mixed>
     */
    private static function claims(array $overrides = []): array
    {
        $claims = array_merge([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'iat' => time(),
            'exp' => time() + 120,
            'jti' => 'jti-' . bin2hex(random_bytes(4)),
            'sub' => 'user-1',
            'sid' => 'sid-1',
            'events' => [JwtVerifier::BACKCHANNEL_LOGOUT_EVENT => new \stdClass()],
        ], $overrides);

        return array_filter($claims, static fn (mixed $value): bool => $value !== null);
    }
}
