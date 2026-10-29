<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Jwt;

use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\JwtTestSigner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[CoversClass(JwtVerifier::class)]
final class JwtVerifierTest extends TestCase
{
    private const JWKS = 'https://idp.example/jwks';
    private const ISSUER = 'https://idp.example';
    private const AUDIENCE = 'client-1';
    private const NONCE = 'nonce-1';

    private JwtTestSigner $signer;

    private MockHttpClient $client;

    protected function setUp(): void
    {
        $this->signer = new JwtTestSigner();
        $signer = $this->signer;
        $this->client = new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson()));
    }

    public function testValidTokenReturnsClaims(): void
    {
        $claims = $this->verify($this->signer->sign($this->claims()));

        self::assertSame('user-1', $claims['sub']);
        self::assertSame(self::NONCE, $claims['nonce']);
    }

    public function testExpiredTokenIsRejected(): void
    {
        $this->expectVerifyFailure('JWT has expired.', $this->signer->sign($this->claims(['exp' => time() - JwtVerifier::LEEWAY_SECONDS - 5])));
    }

    public function testSmallClockSkewIsTolerated(): void
    {
        self::assertSame('user-1', $this->verify($this->signer->sign($this->claims(['exp' => time() - 10, 'iat' => time() + 20])))['sub']);
    }

    public function testMissingIatIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['iat']);

        $this->expectVerifyFailure('iat', $this->signer->sign($claims));
    }

    public function testIatInTheFutureIsRejected(): void
    {
        $this->expectVerifyFailure('issued in the future', $this->signer->sign($this->claims(['iat' => time() + 3600])));
    }

    public function testSeveralAudiencesRequireThisClientAsAuthorizedParty(): void
    {
        $this->expectVerifyFailure('azp', $this->signer->sign($this->claims(['aud' => ['other-client', self::AUDIENCE]])));
    }

    public function testForeignAuthorizedPartyIsRejected(): void
    {
        $this->expectVerifyFailure('azp', $this->signer->sign($this->claims(['azp' => 'other-client'])));
    }

    public function testMissingExpIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['exp']);

        $this->expectVerifyFailure('JWT has expired.', $this->signer->sign($claims));
    }

    public function testNbfInFutureIsRejected(): void
    {
        $this->expectVerifyFailure('JWT is not yet valid.', $this->signer->sign($this->claims(['nbf' => time() + 300])));
    }

    public function testNbfInPastIsAccepted(): void
    {
        $claims = $this->verify($this->signer->sign($this->claims(['nbf' => time() - 60])));

        self::assertSame('user-1', $claims['sub']);
    }

    public function testIssuerMismatchIsRejected(): void
    {
        $this->expectVerifyFailure('issuer', $this->signer->sign($this->claims(['iss' => 'https://evil.example'])));
    }

    public function testMissingIssuerIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['iss']);

        $this->expectVerifyFailure('issuer', $this->signer->sign($claims));
    }

    public function testAudienceStringMatchIsAccepted(): void
    {
        $claims = $this->verify($this->signer->sign($this->claims(['aud' => self::AUDIENCE])));

        self::assertSame(self::AUDIENCE, $claims['aud']);
    }

    public function testAudienceStringMismatchIsRejected(): void
    {
        $this->expectVerifyFailure('audience', $this->signer->sign($this->claims(['aud' => 'other-client'])));
    }

    public function testAudienceArrayContainingClientIdIsAccepted(): void
    {
        $claims = $this->verify($this->signer->sign($this->claims(['aud' => ['other-client', self::AUDIENCE], 'azp' => self::AUDIENCE])));

        self::assertSame(['other-client', self::AUDIENCE], $claims['aud']);
    }

    public function testAudienceArrayWithoutClientIdIsRejected(): void
    {
        $this->expectVerifyFailure('audience', $this->signer->sign($this->claims(['aud' => ['other-client', 'third']])));
    }

    public function testNonceMismatchIsRejected(): void
    {
        $this->expectVerifyFailure('nonce', $this->signer->sign($this->claims(['nonce' => 'attacker-nonce'])));
    }

    public function testMissingNonceIsRejectedWhenExpected(): void
    {
        $claims = $this->claims();
        unset($claims['nonce']);

        $this->expectVerifyFailure('nonce', $this->signer->sign($claims));
    }

    public function testCriticalHeaderIsRejected(): void
    {
        $this->expectVerifyFailure('"crit"', $this->signer->sign($this->claims(['exp2' => 1]), ['crit' => ['exp2']]));
    }

    public function testNonNumericNbfIsRejected(): void
    {
        $this->expectVerifyFailure('"nbf" claim is not a number', $this->signer->sign($this->claims(['nbf' => 'soon'])));
    }

    public function testNonNumericIatIsRejected(): void
    {
        $this->expectVerifyFailure('"iat" claim is not a number', $this->signer->sign($this->claims(['iat' => 'now'])));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonRsaAlgorithms(): iterable
    {
        yield 'ES256' => ['ES256'];
        yield 'PS256' => ['PS256'];
    }

    #[DataProvider('nonRsaAlgorithms')]
    public function testEcAndPssSignedTokensVerify(string $alg): void
    {
        $signer = new JwtTestSigner('k-' . $alg, $alg);
        $client = new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson()));

        $claims = $this->verifyWith(new JwtVerifier($client, new ArrayAdapter(), new NullLogger()), $signer->sign($this->claims()));

        self::assertSame('user-1', $claims['sub']);
    }

    public function testEcKeyIsNotUsedForAnRsaAlgorithm(): void
    {
        // An ES256 key in the JWKS must never be a candidate for an RS256 token with the same kid.
        $ecSigner = new JwtTestSigner('shared', 'ES256');
        $rsaSigner = new JwtTestSigner('shared');
        $client = new MockHttpClient(static fn (): MockResponse => new MockResponse($ecSigner->jwksJson()));

        try {
            $this->verifyWith(new JwtVerifier($client, new ArrayAdapter(), new NullLogger()), $rsaSigner->sign($this->claims()));
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $exception) {
            self::assertStringContainsString('signature verification failed', $exception->getMessage());
        }
    }
    public function testHs256TokenIsRejectedAsUnsupportedAlgorithm(): void
    {
        $this->expectVerifyFailure('Unsupported JWT signature algorithm "HS256"', JwtTestSigner::signHs256($this->claims()));
        self::assertSame(0, $this->client->getRequestsCount());
    }

    public function testBadSignatureWithAKnownKeyIsRejectedWithoutRefetch(): void
    {
        $other = new JwtTestSigner('test-key');

        $this->expectVerifyFailure('signature verification failed', $other->sign($this->claims()));
        // Only the initial JWKS fetch: a known kid can't be a key rotation.
        self::assertSame(1, $this->client->getRequestsCount());
    }

    public function testTamperedPayloadIsRejected(): void
    {
        [$header, , $signature] = explode('.', $this->signer->sign($this->claims()));
        $forgedPayload = rtrim(strtr(base64_encode(json_encode($this->claims(['sub' => 'admin']), \JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        $this->expectVerifyFailure('signature verification failed', $header . '.' . $forgedPayload . '.' . $signature);
    }

    public function testJwksIsFetchedOnceThenServedFromCache(): void
    {
        $verifier = new JwtVerifier($this->client, new ArrayAdapter(), new NullLogger());

        $this->verifyWith($verifier, $this->signer->sign($this->claims()));
        $this->verifyWith($verifier, $this->signer->sign($this->claims(['sub' => 'user-2'])));

        self::assertSame(1, $this->client->getRequestsCount());
    }

    public function testMalformedJwtIsRejected(): void
    {
        $this->expectVerifyFailure('Malformed JWT', 'not-a-jwt');
        self::assertSame(0, $this->client->getRequestsCount());
    }

    public function testJwtWithGarbageSegmentsIsRejected(): void
    {
        $this->expectVerifyFailure('Malformed JWT', 'a.b.c');
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'user-1',
            'exp' => time() + 300,
            'iat' => time(),
            'nonce' => self::NONCE,
        ], $overrides);
    }

    /**
     * @return array<string, mixed>
     */
    private function verify(string $jwt, string $nonce = self::NONCE, ?LoggerInterface $logger = null): array
    {
        return $this->verifyWith(new JwtVerifier($this->client, new ArrayAdapter(), $logger ?? new NullLogger()), $jwt, $nonce);
    }

    /**
     * @return array<string, mixed>
     */
    private function verifyWith(JwtVerifier $verifier, string $jwt, string $nonce = self::NONCE): array
    {
        return $verifier->verify($jwt, self::JWKS, self::ISSUER, self::AUDIENCE, $nonce, 3600, 5);
    }

    private function expectVerifyFailure(string $messageFragment, string $jwt): void
    {
        try {
            $this->verify($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $exception) {
            self::assertStringContainsString($messageFragment, $exception->getMessage());
        }
    }
}
