<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\ScheduledTask;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Cache\DatabaseAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTaskHandler;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Daily housekeeping of the plugin's own tables:
 *
 *  - activity rows whose login is older than
 *    SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS (default 90; 0 = keep forever),
 *    deleted in batches so a large backlog never locks the table for long;
 *  - expired session registry entries and one-time tokens;
 *  - node heartbeats older than a day.
 */
#[AsMessageHandler(handles: SessionActivityCleanupTask::class)]
class SessionActivityCleanupTaskHandler extends ScheduledTaskHandler
{
    private const BATCH_SIZE = 1000;

    public function __construct(
        EntityRepository $scheduledTaskRepository,
        LoggerInterface $exceptionLogger,
        private readonly Connection $connection,
        private readonly int $retentionDays,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly DatabaseAtomicCache $oneTimeTokens,
    ) {
        parent::__construct($scheduledTaskRepository, $exceptionLogger);
    }

    public function run(): void
    {
        if ($this->retentionDays > 0) {
            $before = (new \DateTimeImmutable(sprintf('-%d days', $this->retentionDays), new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT);

            do {
                $deleted = (int) $this->connection->executeStatement(
                    sprintf('DELETE FROM `sw6oidc_session_activity` WHERE `logged_in_at` < :before LIMIT %d', self::BATCH_SIZE),
                    ['before' => $before],
                );
            } while ($deleted === self::BATCH_SIZE);
        }

        $this->sessionRegistry->prune();
        $this->oneTimeTokens->prune();

        $this->connection->executeStatement(
            'DELETE FROM `sw6oidc_node_heartbeat` WHERE `last_seen_at` < :before',
            ['before' => (new \DateTimeImmutable('-1 day', new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT)],
        );
    }
}
