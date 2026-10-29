<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Cache;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Shopware\Core\Defaults;

/**
 * One-time tokens in `sw6oidc_one_time_token`: shared by every app server,
 * unaffected by cache:clear, atomic without Redis. Keys are stored hashed,
 * values encrypted (they carry PKCE verifiers, nonces, user ids).
 *
 * getAndDelete() locks the row (SELECT … FOR UPDATE) and deletes it in the
 * same transaction, so exactly one of several concurrent consumers gets the
 * value. Expired rows are invisible and pruned by prune().
 */
class DatabaseAtomicCache implements AtomicCacheInterface
{
    /** Encryption purpose of one-time token values, also used by RedisAtomicCache. */
    public const VALUE_PURPOSE = 'sw6oidc_one_time_token.value';
    private const PRUNE_BATCH_SIZE = 5000;
    private const PRUNE_TIME_BUDGET_SECONDS = 30;

    public function __construct(
        private readonly Connection $connection,
        private readonly Sw6OidcEncryptor $encryptor,
    ) {
    }

    public function save(string $key, string $value, int $ttlSeconds): void
    {
        $this->connection->executeStatement(
            'REPLACE INTO `sw6oidc_one_time_token` (`key_hash`, `value`, `expires_at`) VALUES (:key, :value, :expiresAt)',
            ['key' => $this->hash($key), 'value' => $this->encryptor->encrypt($value, self::VALUE_PURPOSE), 'expiresAt' => $this->expiresAt($ttlSeconds)],
        );
    }

    public function getAndDelete(string $key): ?string
    {
        $keyHash = $this->hash($key);

        $value = $this->connection->transactional(function (Connection $connection) use ($keyHash): ?string {
            $row = $connection->fetchAssociative(
                'SELECT `value`, `expires_at` FROM `sw6oidc_one_time_token` WHERE `key_hash` = :key FOR UPDATE',
                ['key' => $keyHash],
            );

            if ($row === false) {
                return null;
            }

            $connection->executeStatement('DELETE FROM `sw6oidc_one_time_token` WHERE `key_hash` = :key', ['key' => $keyHash]);

            return (string) $row['expires_at'] > $this->now() ? (string) $row['value'] : null;
        });

        return $value === null ? null : $this->encryptor->decryptOrNull($value, self::VALUE_PURPOSE);
    }

    public function addIfAbsent(string $key, string $value, int $ttlSeconds): bool
    {
        $keyHash = $this->hash($key);

        // An expired marker must not block a new one.
        $this->connection->executeStatement(
            'DELETE FROM `sw6oidc_one_time_token` WHERE `key_hash` = :key AND `expires_at` <= :now',
            ['key' => $keyHash, 'now' => $this->now()],
        );

        try {
            $this->connection->executeStatement(
                'INSERT INTO `sw6oidc_one_time_token` (`key_hash`, `value`, `expires_at`) VALUES (:key, :value, :expiresAt)',
                ['key' => $keyHash, 'value' => $this->encryptor->encrypt($value, self::VALUE_PURPOSE), 'expiresAt' => $this->expiresAt($ttlSeconds)],
            );
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }

    public function delete(string $key): void
    {
        $this->connection->executeStatement('DELETE FROM `sw6oidc_one_time_token` WHERE `key_hash` = :key', ['key' => $this->hash($key)]);
    }

    /**
     * Deletes expired tokens in batches until none are left or the time
     * budget is spent, so a backlog shrinks instead of growing (R3-M17);
     * returns how many.
     */
    public function prune(int $maxSeconds = self::PRUNE_TIME_BUDGET_SECONDS): int
    {
        $deadline = microtime(true) + (float) $maxSeconds;
        $now = $this->now();
        $total = 0;

        do {
            $deleted = (int) $this->connection->executeStatement(
                'DELETE FROM `sw6oidc_one_time_token` WHERE `expires_at` <= :now LIMIT ' . self::PRUNE_BATCH_SIZE,
                ['now' => $now],
            );
            $total += $deleted;
        } while ($deleted === self::PRUNE_BATCH_SIZE && microtime(true) < $deadline);

        return $total;
    }

    private function hash(string $key): string
    {
        return hash('sha256', $key);
    }

    private function now(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT);
    }

    private function expiresAt(int $ttlSeconds): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify(sprintf('+%d seconds', max(1, $ttlSeconds)))->format(Defaults::STORAGE_DATE_TIME_FORMAT);
    }
}
