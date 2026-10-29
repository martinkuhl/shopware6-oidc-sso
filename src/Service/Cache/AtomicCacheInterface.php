<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Cache;

/**
 * Atomic one-time-token storage: OAuth state (PKCE verifier, nonce), admin
 * login hand-off nonces, WebAuthn ceremonies, logout contexts, error tickets
 * and back-channel `jti` replay markers.
 *
 * getAndDelete() must be a single atomic read-and-remove so two concurrent
 * requests can never both consume the same token; addIfAbsent() must be an
 * atomic "set if not exists".
 */
interface AtomicCacheInterface
{
    public function save(string $key, string $value, int $ttlSeconds): void;

    /**
     * Reads and immediately removes the value. Returns null if the key does not
     * exist (already consumed, expired, or never set).
     */
    public function getAndDelete(string $key): ?string;

    /**
     * Stores the value only if the key doesn't exist yet (or has expired).
     * Returns whether this call stored it — false means "already seen".
     */
    public function addIfAbsent(string $key, string $value, int $ttlSeconds): bool;

    /**
     * Removes the key if present (e.g. a replay marker whose work failed, so
     * the sender's retry is processed, R3-M19).
     */
    public function delete(string $key): void;
}
