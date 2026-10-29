<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;

/**
 * A superadmin's decision for the account bindings of a provider whose
 * issuer is about to change (R3-M9): re-bind them to the new issuer (the
 * same identity provider under a new URL) or leave them on the old one,
 * which disconnects them (another tenant: its subjects must never log into
 * these accounts). Set through an API action right before re-saving the
 * provider, valid for five minutes, consumed by the save, keyed by provider
 * and admin.
 */
class IssuerChangeConfirmationStore
{
    public const DECISION_REBIND = 'rebind';
    public const DECISION_DISCONNECT = 'disconnect';

    private const TTL_SECONDS = 300;
    private const PREFIX = 'sw6oidc_issuer_change_';

    public function __construct(private readonly AtomicCacheInterface $store)
    {
    }

    public function confirm(string $providerId, string $userId, bool $rebind): void
    {
        $this->store->save($this->key($providerId, $userId), $rebind ? self::DECISION_REBIND : self::DECISION_DISCONNECT, self::TTL_SECONDS);
    }

    /**
     * @return self::DECISION_*|null
     */
    public function consume(string $providerId, string $userId): ?string
    {
        $decision = $this->store->getAndDelete($this->key($providerId, $userId));

        return \in_array($decision, [self::DECISION_REBIND, self::DECISION_DISCONNECT], true) ? $decision : null;
    }

    private function key(string $providerId, string $userId): string
    {
        return self::PREFIX . strtolower($providerId) . '_' . strtolower($userId);
    }
}
