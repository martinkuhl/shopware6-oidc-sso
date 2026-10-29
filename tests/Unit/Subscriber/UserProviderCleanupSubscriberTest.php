<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Subscriber\UserProviderCleanupSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityWriteResult;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityDeletedEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Shopware\Core\Framework\Uuid\Uuid;

#[CoversClass(UserProviderCleanupSubscriber::class)]
final class UserProviderCleanupSubscriberTest extends TestCase
{
    private UserProviderBindingService&MockObject $bindingService;

    private Connection&MockObject $connection;

    private Sw6OidcSessionRegistry&MockObject $registry;

    private Sw6OidcSessionDestructionService&MockObject $destruction;

    /** @var list<array{string, array<string, mixed>}> */
    private array $statements = [];

    protected function setUp(): void
    {
        $this->bindingService = $this->createMock(UserProviderBindingService::class);
        $this->connection = $this->createMock(Connection::class);
        $this->connection->method('executeStatement')->willReturnCallback(function (string $sql, array $params): int {
            $this->statements[] = [$sql, $params];

            return 1;
        });
        $this->registry = $this->createMock(Sw6OidcSessionRegistry::class);
        $this->destruction = $this->createMock(Sw6OidcSessionDestructionService::class);
    }

    public function testCustomerDeletionRemovesAllPluginDataInSystemScope(): void
    {
        $firstId = Uuid::randomHex();
        $secondId = Uuid::randomHex();
        $unbound = [];

        $this->bindingService->expects(self::exactly(2))
            ->method('unbind')
            ->willReturnCallback(static function (string $userType, string $userId, Context $context) use (&$unbound): void {
                self::assertSame(Context::SYSTEM_SCOPE, $context->getScope());
                $unbound[] = [$userType, $userId];
            });
        $this->registry->expects(self::exactly(2))->method('removeAllForUser');

        $this->subscriber()->onCustomerDeleted($this->deletedEvent('customer', [$firstId, $secondId]));

        self::assertSame([
            [Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $firstId],
            [Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $secondId],
        ], $unbound);
        self::assertCount(4, $this->statements);
        self::assertStringContainsString('sw6oidc_passkey_credential', $this->statements[0][0]);
        self::assertStringContainsString('sw6oidc_session_activity', $this->statements[1][0]);
        self::assertSame(['userType' => 'customer', 'userId' => Uuid::fromHexToBytes($firstId)], $this->statements[0][1]);
    }

    public function testUserDeletionUsesAdminUserType(): void
    {
        $id = Uuid::randomHex();

        $this->bindingService->expects(self::once())
            ->method('unbind')
            ->with(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $id, self::isInstanceOf(Context::class));
        $this->registry->expects(self::once())->method('removeAllForUser')->with('admin', $id);

        $this->subscriber()->onUserDeleted($this->deletedEvent('user', [$id]));
    }

    public function testDeactivationEndsAllSessionsButOtherWritesDoNot(): void
    {
        $deactivated = Uuid::randomHex();

        $this->destruction->expects(self::once())->method('destroyAllForUser')->with('admin', $deactivated);
        $this->registry->expects(self::once())->method('removeAllForUser')->with('admin', $deactivated);

        $this->subscriber()->onUserWritten(new EntityWrittenEvent('user', [
            new EntityWriteResult($deactivated, ['id' => $deactivated, 'active' => false], 'user', EntityWriteResult::OPERATION_UPDATE),
            new EntityWriteResult(Uuid::randomHex(), ['active' => true], 'user', EntityWriteResult::OPERATION_UPDATE),
            new EntityWriteResult(Uuid::randomHex(), ['firstName' => 'X'], 'user', EntityWriteResult::OPERATION_UPDATE),
        ], Context::createDefaultContext()));
    }

    public function testDeactivationFailureDoesNotBreakTheWrite(): void
    {
        $this->destruction->method('destroyAllForUser')->willThrowException(new \RuntimeException('db down'));

        $this->subscriber()->onCustomerWritten(new EntityWrittenEvent('customer', [
            new EntityWriteResult(Uuid::randomHex(), ['active' => false], 'customer', EntityWriteResult::OPERATION_UPDATE),
        ], Context::createDefaultContext()));

        $this->addToAssertionCount(1);
    }

    private function subscriber(): UserProviderCleanupSubscriber
    {
        return new UserProviderCleanupSubscriber($this->bindingService, $this->connection, $this->registry, $this->destruction, new NullLogger());
    }

    /**
     * @param list<string> $ids
     */
    private function deletedEvent(string $entityName, array $ids): EntityDeletedEvent
    {
        $results = array_map(
            static fn (string $id): EntityWriteResult => new EntityWriteResult($id, [], $entityName, EntityWriteResult::OPERATION_DELETE),
            $ids,
        );

        return new EntityDeletedEvent($entityName, $results, Context::createDefaultContext());
    }
}
