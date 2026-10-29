<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Oidc;

use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use MartinKuhl\Sw6Oidc\Controller\Oidc\BackChannelLogoutController;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcIdpLogoutHandler;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\JwtTestSigner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(BackChannelLogoutController::class)]
#[CoversClass(Sw6OidcIdpLogoutHandler::class)]
final class BackChannelLogoutControllerTest extends TestCase
{
    private const ISSUER = 'https://idp.example';

    private JwtTestSigner $signer;

    private Sw6OidcSessionRegistry $registry;

    /** @var list<Sw6OidcSession> */
    private array $destroyed = [];

    private Sw6OidcRateLimiter $rateLimiter;

    private InMemoryAtomicCache $replayMarkers;

    private bool $failNextDestroy = false;

    protected function setUp(): void
    {
        $this->signer = new JwtTestSigner();
        $this->registry = SqliteSessionRegistry::create();
        $this->rateLimiter = new Sw6OidcRateLimiter(null, new ArrayAdapter());
        $this->replayMarkers = new InMemoryAtomicCache();
    }

    public function testValidTokenWithSidEndsExactlyThatSession(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-2', 'customer', 'c1000000000000000000000000000001', 'ctx-2', '5c000000000000000000000000000001');

        $response = $this->post($this->token(['sid' => 'sid-1']));

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertSame(['ctx-1'], array_map(static fn (Sw6OidcSession $s): string => $s->sessionKey, $this->destroyed));
        self::assertCount(1, $this->registry->resolve('a1000000000000000000000000000001', 'user-1'));
    }

    public function testValidTokenWithSubOnlyEndsAllSessionsOfTheSubject(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-2', 'customer', 'c1000000000000000000000000000001', 'ctx-2', '5c000000000000000000000000000001');

        self::assertSame(200, $this->post($this->token(['sid' => null]))->getStatusCode());
        self::assertCount(2, $this->destroyed);
    }

    public function testSubSidMismatchEndsNothing(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');

        self::assertSame(200, $this->post($this->token(['sub' => 'someone-else', 'sid' => 'sid-1']))->getStatusCode());
        self::assertSame([], $this->destroyed);
    }

    public function testUnknownSessionIsStillSuccess(): void
    {
        self::assertSame(200, $this->post($this->token(['sid' => 'unknown']))->getStatusCode());
        self::assertSame([], $this->destroyed);
    }

    public function testAdminSessionsOfOneUserAreDestroyedOnce(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'admin', 'e1000000000000000000000000000001', 'jti-1');
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-2', 'admin', 'e1000000000000000000000000000001', 'jti-2');

        $this->post($this->token(['sid' => null]));

        self::assertCount(1, $this->destroyed);
        self::assertSame([], SqliteSessionRegistry::sessionsOf($this->registry, 'admin', 'e1000000000000000000000000000001'), 'both registry entries are removed');
    }

    public function testReplayedTokenIsAcceptedButNotProcessedTwice(): void
    {
        $token = $this->token(['jti' => 'same-jti']);
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');
        $controller = $this->controller();

        $first = $controller->logout($this->request($token));
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-again', '5c000000000000000000000000000001');
        $replay = $controller->logout($this->request($token));

        self::assertSame([200, 200], [$first->getStatusCode(), $replay->getStatusCode()]);

        self::assertSame(['ctx-1'], array_map(static fn (Sw6OidcSession $s): string => $s->sessionKey, $this->destroyed));
    }

    /**
     * R3-M19: a failure halfway must leave the session targetable and the
     * token retryable, not "already seen".
     */
    public function testAFailedLogoutCanBeRetried(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');
        $token = $this->token(['jti' => 'retried-jti']);
        $this->failNextDestroy = true;

        self::assertSame(500, $this->post($token)->getStatusCode());
        self::assertCount(1, $this->registry->resolveBySid('a1000000000000000000000000000001', 'sid-1'));
        self::assertSame([], $this->destroyed);

        self::assertSame(200, $this->post($token)->getStatusCode());
        self::assertCount(1, $this->destroyed);
        self::assertSame([], $this->registry->resolveBySid('a1000000000000000000000000000001', 'sid-1'));
    }

    public function testMissingTokenIs400(): void
    {
        self::assertSame(400, $this->controller()->logout(Request::create('/sw6oidc/backchannel-logout', 'POST'))->getStatusCode());
    }

    public function testUnknownIssuerIs400(): void
    {
        self::assertSame(400, $this->post($this->token(['iss' => 'https://unknown.example']))->getStatusCode());
    }

    public function testAudienceOfAnotherClientIs400(): void
    {
        self::assertSame(400, $this->post($this->token(['aud' => 'other-client']))->getStatusCode());
    }

    public function testForgedSignatureIs400AndEndsNothing(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'user-1', 'sid-1', 'customer', 'c1000000000000000000000000000001', 'ctx-1', '5c000000000000000000000000000001');

        $forged = (new JwtTestSigner('attacker'))->sign($this->claims([]));

        self::assertSame(400, $this->post($forged)->getStatusCode());
        self::assertSame([], $this->destroyed);
    }

    public function testIdTokenCannotBeReplayedAsLogoutToken(): void
    {
        self::assertSame(400, $this->post($this->token(['events' => null, 'nonce' => 'n']))->getStatusCode());
    }

    public function testRepeatedForgedTokensAreRateLimitedButAValidTokenStillWorks(): void
    {
        $controller = $this->controller();
        $forged = (new JwtTestSigner('attacker'))->sign($this->claims([]));

        for ($i = 0; $i < 10; ++$i) {
            self::assertSame(400, $controller->logout($this->request($forged))->getStatusCode());
        }

        self::assertSame(429, $controller->logout($this->request($forged))->getStatusCode());
        // SaaS IdPs share egress IPs: the real IdP's signed token is never refused (N-M7).
        self::assertSame(200, $controller->logout($this->request($this->token([])))->getStatusCode());
    }

    public function testGarbageFromAnAddressDoesNotBlockValidLogoutTokens(): void
    {
        $controller = $this->controller();

        for ($i = 0; $i < 15; ++$i) {
            $controller->logout($this->request('garbage'));
        }

        self::assertSame(200, $controller->logout($this->request($this->token([])))->getStatusCode());
    }

    public function testTokenWithoutJtiIsRejected(): void
    {
        $claims = $this->claims([]);
        unset($claims['jti']);

        self::assertSame(400, $this->post($this->signer->sign($claims))->getStatusCode());
    }

    public function testStaleTokenIsRejected(): void
    {
        self::assertSame(400, $this->post($this->token(['iat' => time() - 3600, 'exp' => time() + 60]))->getStatusCode());
    }

    public function testErrorsRevealNothingToTheCaller(): void
    {
        $body = (string) $this->post($this->token(['iss' => 'https://unknown.example']))->getContent();

        self::assertSame('{"error":"invalid_request"}', $body);
    }

    public function testValidRequestsNeverTriggerTheRateLimit(): void
    {
        $controller = $this->controller();

        for ($i = 0; $i < 15; ++$i) {
            self::assertSame(200, $controller->logout($this->request($this->token([])))->getStatusCode());
        }
    }

    private function post(string $token): Response
    {
        return $this->controller()->logout($this->request($token));
    }

    private function request(string $token): Request
    {
        return Request::create('https://shop.example/sw6oidc/backchannel-logout', 'POST', ['logout_token' => $token], [], [], ['REMOTE_ADDR' => '203.0.113.5']);
    }

    private function controller(): BackChannelLogoutController
    {
        $signer = $this->signer;
        $verifier = new JwtVerifier(new MockHttpClient(static fn (): MockResponse => new MockResponse($signer->jwksJson())), new ArrayAdapter(), new NullLogger());

        $provider = new Sw6OidcProviderEntity();
        $provider->assign(['id' => 'a1000000000000000000000000000001', 'clientId' => 'client-1', 'issuer' => self::ISSUER, 'jwksEndpoint' => 'https://idp.example/jwks', 'jwksCacheTtl' => 60, 'httpTimeout' => 5]);

        $resolver = $this->createStub(ProviderResolver::class);
        $resolver->method('findByIssuer')->willReturnCallback(static fn (string $issuer): array => $issuer === self::ISSUER ? [$provider] : []);

        $destruction = $this->createStub(Sw6OidcSessionDestructionService::class);
        $destruction->method('destroy')->willReturnCallback(function (Sw6OidcSession $session): void {
            if ($this->failNextDestroy) {
                $this->failNextDestroy = false;

                throw new \RuntimeException('Lock wait timeout exceeded');
            }

            $this->destroyed[] = $session;
        });

        return new BackChannelLogoutController(
            $verifier,
            $resolver,
            new Sw6OidcIdpLogoutHandler($this->registry, $destruction, new NullLogger(), $this->createStub(Sw6OidcSessionActivityRecorder::class)),
            $this->rateLimiter,
            $this->replayMarkers,
            new NullLogger(),
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function token(array $overrides): string
    {
        return $this->signer->sign($this->claims($overrides));
    }

    /**
     * @param array<string, mixed> $overrides null removes the claim
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides): array
    {
        return array_filter(array_merge([
            'iss' => self::ISSUER,
            'aud' => 'client-1',
            'iat' => time(),
            'exp' => time() + 120,
            'jti' => bin2hex(random_bytes(8)),
            'sub' => 'user-1',
            'sid' => 'sid-1',
            'events' => [JwtVerifier::BACKCHANNEL_LOGOUT_EVENT => new \stdClass()],
        ], $overrides), static fn (mixed $value): bool => $value !== null);
    }
}
