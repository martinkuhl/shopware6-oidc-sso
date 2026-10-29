<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Maps IdP subjects / IdP sessions (`sub`, `sid`, both scoped to the
 * provider — they are only unique per issuer) and local accounts to the
 * local sessions an OIDC login created, so Back-/Front-Channel Logout and
 * forced logouts can find what to destroy.
 *
 * This is security state, so it lives in the `sw6oidc_session` table rather
 * than a cache pool that cache:clear or a deploy would empty: an IdP logout
 * must find a session for as long as that session can be used. Both admin
 * refresh tokens and customer context tokens slide with activity, so a fixed
 * lifetime would expire entries of sessions still in use (R3-H5). Instead
 * an entry lives as long as core's own session state does — the admin has
 * an unexpired refresh token, the customer's context in that sales channel
 * was used within the context lifetime — and `expires_at` is only a hard
 * upper bound (HARD_TTL_SECONDS). The daily cleanup task prunes the rest.
 * Session keys (context tokens / jtis) and IdP tokens are credentials:
 * stored encrypted, looked up by hash.
 */
class Sw6OidcSessionRegistry
{
    /** Encryption purpose of a column: `sw6oidc_session.<column>`. */
    private const PURPOSE_PREFIX = 'sw6oidc_session.';

    /** Hard upper bound for any entry; liveness comes from core's session state (R3-H5). */
    public const HARD_TTL_SECONDS = 7776000;

    /** Entries younger than this are never pruned for liveness (an admin login between callback and token exchange). */
    private const LIVENESS_GRACE_SECONDS = 3600;

    private readonly int $customerContextLifetimeSeconds;

    /**
     * @param string $customerContextLifetime ISO 8601 duration, `shopware.api.store.context_lifetime`
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly Sw6OidcEncryptor $encryptor,
        private readonly LoggerInterface $logger,
        string $customerContextLifetime = 'P1D',
    ) {
        $this->customerContextLifetimeSeconds = (new \DateTimeImmutable('@0'))->add(new \DateInterval($customerContextLifetime))->getTimestamp();
    }

    public function register(
        string $providerId,
        string $sub,
        ?string $sid,
        string $userType,
        string $userId,
        string $sessionKey,
        ?string $salesChannelId = null,
        ?string $idToken = null,
        ?string $idpAccessToken = null,
        ?string $idpRefreshToken = null,
        ?int $ttlSeconds = null,
    ): Sw6OidcSession {
        $session = new Sw6OidcSession(
            bin2hex(random_bytes(16)),
            $providerId,
            $sub,
            $sid !== '' ? $sid : null,
            $userType,
            $userId,
            $sessionKey,
            $salesChannelId,
            $idToken,
            time(),
            $idpAccessToken,
            $idpRefreshToken,
        );

        $ttl = $ttlSeconds ?? self::HARD_TTL_SECONDS;

        $this->connection->insert('sw6oidc_session', [
            'id' => $session->id,
            'provider_id' => Uuid::fromHexToBytes($providerId),
            'sub' => $sub,
            'sid' => $session->sid,
            'user_type' => $userType,
            'user_id' => Uuid::fromHexToBytes($userId),
            'session_key' => $this->encryptor->encrypt($sessionKey, self::PURPOSE_PREFIX . 'session_key'),
            'session_key_hash' => self::hashSessionKey($sessionKey),
            'sales_channel_id' => $salesChannelId !== null ? Uuid::fromHexToBytes($salesChannelId) : null,
            'id_token' => $this->encryptNullable($idToken, 'id_token'),
            'idp_access_token' => $this->encryptNullable($idpAccessToken, 'idp_access_token'),
            'idp_refresh_token' => $this->encryptNullable($idpRefreshToken, 'idp_refresh_token'),
            'created_at' => (new \DateTimeImmutable('@' . $session->createdAt))->format(Defaults::STORAGE_DATE_TIME_FORMAT),
            'expires_at' => $this->expiresAt($ttl),
        ]);

        $this->logger->debug('sw6oidc: session registered.', [
            'providerId' => $providerId,
            'userType' => $userType,
            'userId' => $userId,
            'hasSid' => $session->sid !== null,
        ]);

        return $session;
    }

    /**
     * All live sessions of an IdP subject at this provider.
     *
     * @return list<Sw6OidcSession>
     */
    public function resolve(string $providerId, string $sub): array
    {
        return $this->fetch('`provider_id` = :providerId AND `sub` = :sub', [
            'providerId' => Uuid::fromHexToBytes($providerId),
            'sub' => $sub,
        ]);
    }

    /**
     * @return list<Sw6OidcSession>
     */
    public function resolveBySid(string $providerId, string $sid): array
    {
        return $this->fetch('`provider_id` = :providerId AND `sid` = :sid', [
            'providerId' => Uuid::fromHexToBytes($providerId),
            'sid' => $sid,
        ]);
    }


    /**
     * The account's session created with this session key (context token /
     * first jti), if still registered.
     */
    public function findBySessionKey(string $userType, string $userId, string $sessionKey): ?Sw6OidcSession
    {
        return $this->fetch('`user_type` = :userType AND `user_id` = :userId AND `session_key_hash` = :hash', [
            'userType' => $userType,
            'userId' => Uuid::fromHexToBytes($userId),
            'hash' => self::hashSessionKey($sessionKey),
        ])[0] ?? null;
    }

    /**
     * The account's session with this registry id — for admins the
     * login-session handle the Administration sends back at logout.
     */
    public function findForUser(string $userType, string $userId, string $id): ?Sw6OidcSession
    {
        return $this->fetch('`user_type` = :userType AND `user_id` = :userId AND `id` = :id', [
            'userType' => $userType,
            'userId' => Uuid::fromHexToBytes($userId),
            'id' => $id,
        ])[0] ?? null;
    }

    /**
     * Completes an entry registered before its session existed (admin OIDC:
     * the callback registers, the nonce exchange mints the access token):
     * sets the real session key and the hard upper bound (liveness then
     * follows the admin's refresh tokens).
     */
    public function activate(string $id, string $sessionKey): void
    {
        $this->connection->executeStatement(
            'UPDATE `sw6oidc_session` SET `session_key` = :key, `session_key_hash` = :hash, `expires_at` = :expiresAt WHERE `id` = :id',
            [
                'id' => $id,
                'key' => $this->encryptor->encrypt($sessionKey, self::PURPOSE_PREFIX . 'session_key'),
                'hash' => self::hashSessionKey($sessionKey),
                'expiresAt' => $this->expiresAt(self::HARD_TTL_SECONDS),
            ],
        );
    }

    public function remove(Sw6OidcSession $session): void
    {
        $this->connection->delete('sw6oidc_session', ['id' => $session->id]);
    }

    /**
     * Removes every registered session of the account; returns how many.
     */
    public function removeAllForUser(string $userType, string $userId): int
    {
        return (int) $this->connection->delete('sw6oidc_session', [
            'user_type' => $userType,
            'user_id' => Uuid::fromHexToBytes($userId),
        ]);
    }

    public function get(string $id): ?Sw6OidcSession
    {
        return $this->fetch('`id` = :id', ['id' => $id])[0] ?? null;
    }

    /**
     * Deletes entries past their hard upper bound and entries whose session
     * core no longer has (R3-H5); returns how many.
     */
    public function prune(): int
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $graceCutoff = $now->modify(sprintf('-%d seconds', self::LIVENESS_GRACE_SECONDS))->format(Defaults::STORAGE_DATE_TIME_FORMAT);

        $deleted = (int) $this->connection->executeStatement(
            'DELETE FROM `sw6oidc_session` WHERE `expires_at` <= :now',
            ['now' => $now->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
        );

        // Admins: a session lives as long as one of the admin's refresh tokens.
        $deleted += (int) $this->connection->executeStatement(
            <<<'SQL'
                DELETE FROM `sw6oidc_session`
                WHERE `user_type` = 'admin'
                  AND `created_at` < :graceCutoff
                  AND NOT EXISTS (
                      SELECT 1 FROM `refresh_token`
                      WHERE `refresh_token`.`user_id` = `sw6oidc_session`.`user_id` AND `refresh_token`.`expires_at` > :now
                  )
            SQL,
            ['graceCutoff' => $graceCutoff, 'now' => $now->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
        );

        // Customers: core keeps one context per customer and sales channel; it
        // counts while it was used within the context lifetime.
        $deleted += (int) $this->connection->executeStatement(
            <<<'SQL'
                DELETE FROM `sw6oidc_session`
                WHERE `user_type` = 'customer'
                  AND `created_at` < :graceCutoff
                  AND NOT EXISTS (
                      SELECT 1 FROM `sales_channel_api_context`
                      WHERE `sales_channel_api_context`.`customer_id` = `sw6oidc_session`.`user_id`
                        AND `sales_channel_api_context`.`sales_channel_id` = `sw6oidc_session`.`sales_channel_id`
                        AND `sales_channel_api_context`.`updated_at` > :contextCutoff
                  )
            SQL,
            [
                'graceCutoff' => $graceCutoff,
                'contextCutoff' => $now->modify(sprintf('-%d seconds', $this->customerContextLifetimeSeconds))->format(Defaults::STORAGE_DATE_TIME_FORMAT),
            ],
        );

        return $deleted;
    }

    private function expiresAt(int $ttlSeconds): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify(sprintf('+%d seconds', $ttlSeconds))->format(Defaults::STORAGE_DATE_TIME_FORMAT);
    }


    public static function hashSessionKey(string $sessionKey): string
    {
        return hash('sha256', $sessionKey);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return list<Sw6OidcSession>
     */
    private function fetch(string $where, array $parameters): array
    {
        $rows = $this->connection->fetchAllAssociative(
            'SELECT * FROM `sw6oidc_session` WHERE ' . $where . ' AND `expires_at` > :now ORDER BY `created_at` ASC',
            [...$parameters, 'now' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
        );

        $sessions = [];

        foreach ($rows as $row) {
            $session = $this->hydrate($row);

            if ($session instanceof Sw6OidcSession) {
                $sessions[] = $session;
            }
        }

        return $sessions;
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): ?Sw6OidcSession
    {
        $sessionKey = $this->encryptor->decryptOrNull((string) $row['session_key'], self::PURPOSE_PREFIX . 'session_key');

        if ($sessionKey === null) {
            // Written under a different APP_SECRET: the session can't be targeted anymore.
            return null;
        }

        $createdAt = \DateTimeImmutable::createFromFormat(Defaults::STORAGE_DATE_TIME_FORMAT, (string) $row['created_at'], new \DateTimeZone('UTC'));

        return new Sw6OidcSession(
            (string) $row['id'],
            Uuid::fromBytesToHex((string) $row['provider_id']),
            (string) $row['sub'],
            \is_string($row['sid']) ? $row['sid'] : null,
            (string) $row['user_type'],
            Uuid::fromBytesToHex((string) $row['user_id']),
            $sessionKey,
            \is_string($row['sales_channel_id']) ? Uuid::fromBytesToHex($row['sales_channel_id']) : null,
            $this->decryptNullable($row['id_token'], 'id_token'),
            $createdAt !== false ? $createdAt->getTimestamp() : 0,
            $this->decryptNullable($row['idp_access_token'], 'idp_access_token'),
            $this->decryptNullable($row['idp_refresh_token'], 'idp_refresh_token'),
        );
    }

    private function encryptNullable(?string $value, string $column): ?string
    {
        return $value === null || $value === '' ? null : $this->encryptor->encrypt($value, self::PURPOSE_PREFIX . $column);
    }

    private function decryptNullable(mixed $value, string $column): ?string
    {
        return \is_string($value) ? $this->encryptor->decryptOrNull($value, self::PURPOSE_PREFIX . $column) : null;
    }
}
