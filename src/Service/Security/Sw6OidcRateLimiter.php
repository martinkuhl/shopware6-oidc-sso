<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\RateLimiter\LimiterInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

/**
 * Per-client-address rate limiting for the plugin's anonymous endpoints.
 * Built directly on Symfony's RateLimiterFactory — a plugin cannot register
 * limiters into Shopware core's own `shopware.api.rate_limiter` registry.
 *
 * Two budgets, each kept per scope, so one endpoint can never lock another
 * (N-M3):
 * - **Consuming** (consume(), 30 per 60 s): every request counts. For
 *   endpoints whose *successful* requests create state — flow start and
 *   passkey options each write a cache/DB entry — which a failure-only
 *   budget could never stop (N-M15, M5).
 * - **Failure-only** (isBlocked() peeks, recordFailure() counts, 10 per
 *   60 s): for endpoints that redeem something (callbacks after a valid
 *   state, nonce exchange, passkey verify, error tickets, step-up, logout
 *   tokens). A busy IdP or an office behind one NAT address is never
 *   throttled by its successful requests.
 *
 * Addresses are keyed as given by Request::getClientIp(), IPv6 by its /64 (a
 * single host usually controls a whole /64). Behind a reverse proxy or CDN,
 * `framework.trusted_proxies` MUST be configured, or every client shares the
 * proxy's address and budget.
 *
 * Storage is Shopware's `cache.rate_limiter` pool when present (shared across
 * nodes), else `cache.app`. No lock: a race can let a few extra requests
 * through, which is fine for this purpose.
 */
class Sw6OidcRateLimiter
{
    public const SCOPE_BACKCHANNEL_LOGOUT = 'backchannel_logout';
    public const SCOPE_FRONTCHANNEL_LOGOUT = 'frontchannel_logout';
    public const SCOPE_CALLBACK_STOREFRONT = 'callback_storefront';
    public const SCOPE_CALLBACK_ADMIN = 'callback_admin';
    public const SCOPE_FLOW_START = 'flow_start';
    public const SCOPE_OPTIONS = 'options';
    public const SCOPE_REDEEM = 'redeem';

    private readonly RateLimiterFactory $failureFactory;

    private readonly RateLimiterFactory $consumingFactory;

    public function __construct(
        ?CacheItemPoolInterface $rateLimiterPool,
        CacheItemPoolInterface $fallbackPool,
        int $failureLimit = 10,
        int $intervalSeconds = 60,
        int $consumingLimit = 30,
    ) {
        $storage = new CacheStorage($rateLimiterPool ?? $fallbackPool);

        $this->failureFactory = new RateLimiterFactory(
            ['id' => 'sw6oidc', 'policy' => 'fixed_window', 'limit' => $failureLimit, 'interval' => $intervalSeconds . ' seconds'],
            $storage,
        );
        $this->consumingFactory = new RateLimiterFactory(
            ['id' => 'sw6oidc_req', 'policy' => 'fixed_window', 'limit' => $consumingLimit, 'interval' => $intervalSeconds . ' seconds'],
            $storage,
        );
    }

    /**
     * Counts this request; false once the address used up the scope's budget.
     */
    public function consume(string $scope, ?string $clientIp): bool
    {
        return $this->consumingFactory->create($this->key($scope, $clientIp))->consume(1)->isAccepted();
    }

    public function isBlocked(string $scope, ?string $clientIp): bool
    {
        return $this->failureLimiter($scope, $clientIp)->consume(0)->getRemainingTokens() === 0;
    }

    public function recordFailure(string $scope, ?string $clientIp): void
    {
        $this->failureLimiter($scope, $clientIp)->consume(1);
    }

    /**
     * The address a budget is kept for: IPv4 as is, IPv6 by its /64.
     */
    private function clientKey(?string $clientIp): string
    {
        if ($clientIp === null || $clientIp === '') {
            return 'unknown';
        }

        if (filter_var($clientIp, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) !== false) {
            // anonymize() zeroes the last 8 bytes of an IPv6 address: its /64.
            return IpUtils::anonymize($clientIp) . '/64';
        }

        return $clientIp;
    }

    private function failureLimiter(string $scope, ?string $clientIp): LimiterInterface
    {
        return $this->failureFactory->create($this->key($scope, $clientIp));
    }

    private function key(string $scope, ?string $clientIp): string
    {
        return $scope . '-' . hash('sha256', $this->clientKey($clientIp));
    }
}
