<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;

/**
 * Fallback for Administration logout when the exact login session can't be
 * identified (the Administration lost its login-session handle): remembers
 * which provider the admin last logged in through, so logout can still
 * redirect to the right `end_session_endpoint`. Only the provider id is kept
 * (no id_token — that lives once, encrypted, in the session registry), and
 * only the newest login per admin (last login wins).
 */
class LogoutContextStore
{
    private const TTL_SECONDS = 2592000;
    private const ADMIN_CACHE_PREFIX = 'sw6oidc_admin_logout_ctx_';

    public function __construct(private readonly AtomicCacheInterface $cache)
    {
    }

    public function rememberForAdmin(string $userId, string $providerId): void
    {
        $this->cache->save(self::ADMIN_CACHE_PREFIX . $userId, $providerId, self::TTL_SECONDS);
    }

    public function consumeForAdmin(string $userId): ?LogoutContext
    {
        $providerId = $this->cache->getAndDelete(self::ADMIN_CACHE_PREFIX . $userId);

        return $providerId === null || $providerId === '' ? null : new LogoutContext($providerId);
    }
}
