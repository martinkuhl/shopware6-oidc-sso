<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Api;

use MartinKuhl\Sw6Oidc\Controller\Api\OidcAdminAuthController;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\BuildsOidcAdminAuthController;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(OidcAdminAuthController::class)]
final class OidcAdminAuthControllerRateLimitTest extends TestCase
{
    use BuildsOidcAdminAuthController;

    public function testFlowStartHasAConsumingBudget(): void
    {
        $resolver = $this->createMock(ProviderResolver::class);
        $resolver->method('resolveDefault')->willThrowException(new ProviderNotFoundException('none'));

        $controller = $this->buildAdminAuthController([
            'providerResolver' => $resolver,
            'rateLimiter' => new Sw6OidcRateLimiter(null, new ArrayAdapter(), 10, 60, 2),
        ]);

        self::assertStringContainsString('provider_unavailable', $this->location($controller->login(self::request())));
        self::assertStringContainsString('provider_unavailable', $this->location($controller->login(self::request())));
        self::assertStringContainsString('sw6oidc_error=oidc_failed', $this->location($controller->login(self::request())));
    }

    public function testUnknownNoncesAreCountedAndEventuallyRefused(): void
    {
        $controller = $this->buildAdminAuthController(['rateLimiter' => new Sw6OidcRateLimiter(null, new ArrayAdapter(), 2)]);

        $statuses = [];

        for ($i = 0; $i < 3; ++$i) {
            $statuses[] = $controller->exchangeNonce(self::request(['sw6oidc_nonce' => 'nope']))->getStatusCode();
        }

        self::assertSame([Response::HTTP_BAD_REQUEST, Response::HTTP_BAD_REQUEST, Response::HTTP_TOO_MANY_REQUESTS], $statuses);
    }

    public function testUnknownErrorTicketsAreCounted(): void
    {
        $controller = $this->buildAdminAuthController(['rateLimiter' => new Sw6OidcRateLimiter(null, new ArrayAdapter(), 1)]);

        self::assertSame(Response::HTTP_OK, $controller->loginError('unknown', self::request())->getStatusCode());
        self::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $controller->loginError('unknown', self::request())->getStatusCode());
    }

    /**
     * @param array<string, string> $body
     */
    private static function request(array $body = []): Request
    {
        return new Request([], $body, [], [], [], ['REMOTE_ADDR' => '198.51.100.7']);
    }

    private function location(Response $response): string
    {
        self::assertInstanceOf(RedirectResponse::class, $response);

        return $response->getTargetUrl();
    }
}
