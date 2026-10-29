<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\ScheduledTask;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\ScheduledTask\SessionActivityCleanupTask;
use MartinKuhl\Sw6Oidc\ScheduledTask\SessionActivityCleanupTaskHandler;
use MartinKuhl\Sw6Oidc\Service\Cache\DatabaseAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;

#[CoversClass(SessionActivityCleanupTaskHandler::class)]
#[CoversClass(SessionActivityCleanupTask::class)]
final class SessionActivityCleanupTaskHandlerTest extends TestCase
{
    public function testDeletesActivityOlderThanTheRetentionInBatches(): void
    {
        $statements = [];
        $connection = $this->createMock(Connection::class);
        $connection->method('executeStatement')->willReturnCallback(static function (string $sql, array $params) use (&$statements): int {
            $statements[] = [$sql, $params];

            // First activity batch is full, the second one isn't.
            return str_contains($sql, 'sw6oidc_session_activity') ? (\count($statements) === 1 ? 1000 : 3) : 0;
        });

        $this->handler($connection, 30)->run();

        $activityDeletes = array_values(array_filter($statements, static fn (array $s): bool => str_contains($s[0], 'DELETE FROM `sw6oidc_session_activity`')));
        self::assertCount(2, $activityDeletes);
        self::assertStringContainsString('LIMIT 1000', $activityDeletes[0][0]);
        $before = new \DateTimeImmutable($activityDeletes[0][1]['before'], new \DateTimeZone('UTC'));
        self::assertLessThan(5, abs($before->getTimestamp() - strtotime('-30 days')));
    }

    public function testZeroRetentionKeepsActivityButStillPrunesState(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('executeStatement')->with(self::stringContains('sw6oidc_node_heartbeat'));

        $registry = $this->createMock(Sw6OidcSessionRegistry::class);
        $registry->expects(self::once())->method('prune');
        $tokens = $this->createMock(DatabaseAtomicCache::class);
        $tokens->expects(self::once())->method('prune');

        (new SessionActivityCleanupTaskHandler($this->createMock(EntityRepository::class), new NullLogger(), $connection, 0, $registry, $tokens))->run();
    }

    public function testTaskRunsDaily(): void
    {
        self::assertSame('sw6oidc.session_activity_cleanup', SessionActivityCleanupTask::getTaskName());
        self::assertSame(86400, SessionActivityCleanupTask::getDefaultInterval());
    }

    private function handler(Connection $connection, int $retentionDays): SessionActivityCleanupTaskHandler
    {
        return new SessionActivityCleanupTaskHandler(
            $this->createMock(EntityRepository::class),
            new NullLogger(),
            $connection,
            $retentionDays,
            $this->createStub(Sw6OidcSessionRegistry::class),
            $this->createStub(DatabaseAtomicCache::class),
        );
    }
}
