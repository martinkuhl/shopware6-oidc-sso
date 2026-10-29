<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use Doctrine\DBAL\Connection;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;

/**
 * Records which web nodes (hostnames) recently handled SSO logins or the
 * health endpoint — never the message worker (R3-L32) — so the health check can tell a multi-node setup — where
 * node-local caches (rate limiter, JWKS) diverge and Redis is recommended —
 * from a single server. Never throws.
 */
class NodeHeartbeat
{
    /** At most one write per process and window: the health endpoint may be polled every few seconds. */
    private const MIN_INTERVAL_SECONDS = 60;

    private static int $lastRecordedAt = 0;

    public function __construct(
        private readonly Connection $connection,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function record(): void
    {
        if (time() - self::$lastRecordedAt < self::MIN_INTERVAL_SECONDS) {
            return;
        }

        self::$lastRecordedAt = time();

        try {
            $this->connection->executeStatement(
                'INSERT INTO `sw6oidc_node_heartbeat` (`hostname`, `last_seen_at`) VALUES (:hostname, :now)
                 ON DUPLICATE KEY UPDATE `last_seen_at` = VALUES(`last_seen_at`)',
                ['hostname' => $this->hostname(), 'now' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
            );
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: could not record the node heartbeat.', ['exceptionClass' => $exception::class]);
        }
    }

    /**
     * Distinct nodes seen within the window.
     */
    public function recentNodeCount(int $windowSeconds = 900): int
    {
        try {
            return (int) $this->connection->fetchOne(
                'SELECT COUNT(*) FROM `sw6oidc_node_heartbeat` WHERE `last_seen_at` >= :since',
                ['since' => (new \DateTimeImmutable(sprintf('-%d seconds', $windowSeconds), new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
            );
        } catch (\Throwable) {
            return 0;
        }
    }

    private function hostname(): string
    {
        $hostname = gethostname();

        return substr($hostname !== false && $hostname !== '' ? $hostname : 'unknown', 0, 255);
    }
}
