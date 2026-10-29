<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;

/**
 * The explicit "yes, lock out the admins without SSO binding" confirmation
 * for switching Administration password login off. The Administration sets
 * it through an API action right before re-saving the provider (a DAL save
 * can't carry extra request data); it is valid for five minutes and consumed
 * by the first write guard check.
 *
 * Kept in the atomic store (database unless Redis is configured), so it
 * works across nodes and survives a cache clear, and keyed by provider *and*
 * confirming admin: another admin's save can't consume it (R3-M22).
 */
class LockoutConfirmationStore
{
    private const TTL_SECONDS = 300;
    private const PREFIX = 'sw6oidc_lockout_confirm_';

    public function __construct(private readonly AtomicCacheInterface $store)
    {
    }

    public function confirm(string $providerId, string $userId): void
    {
        $this->store->save($this->key($providerId, $userId), '1', self::TTL_SECONDS);
    }

    public function consume(string $providerId, string $userId): bool
    {
        return $this->store->getAndDelete($this->key($providerId, $userId)) !== null;
    }

    private function key(string $providerId, string $userId): string
    {
        return self::PREFIX . strtolower($providerId) . '_' . strtolower($userId);
    }
}
