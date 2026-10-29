<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Session;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Uuid\Uuid;

#[CoversClass(Sw6OidcSessionRegistry::class)]
#[CoversClass(Sw6OidcSession::class)]
final class Sw6OidcSessionRegistryTest extends TestCase
{
    private Sw6OidcSessionRegistry $registry;

    private Connection $connection;

    private string $providerId;

    private string $customerId;

    protected function setUp(): void
    {
        $this->connection = SqliteSessionRegistry::connection();
        $this->registry = SqliteSessionRegistry::create($this->connection);
        $this->providerId = Uuid::randomHex();
        $this->customerId = Uuid::randomHex();
    }

    public function testRegisteredSessionResolvesBySubSidAndUser(): void
    {
        $salesChannelId = Uuid::randomHex();
        $session = $this->registry->register($this->providerId, 'user|42', 'sid-a', 'customer', $this->customerId, 'ctx-token', $salesChannelId, 'id.token.value', 'at', 'rt');

        self::assertEquals([$session], $this->registry->resolve($this->providerId, 'user|42'));
        self::assertEquals([$session], $this->registry->resolveBySid($this->providerId, 'sid-a'));
        self::assertEquals([$session], SqliteSessionRegistry::sessionsOf($this->registry, 'customer', $this->customerId));
        self::assertEquals($session, $this->registry->findBySessionKey('customer', $this->customerId, 'ctx-token'));

        $stored = $this->registry->get($session->id);
        self::assertNotNull($stored);
        self::assertSame($salesChannelId, $stored->salesChannelId);
        self::assertSame('id.token.value', $stored->idToken);
        self::assertSame('at', $stored->idpAccessToken);
        self::assertSame('rt', $stored->idpRefreshToken);
    }

    public function testCredentialsAreNeverStoredInPlaintext(): void
    {
        $this->registry->register($this->providerId, 'sub', null, 'customer', $this->customerId, 'ctx-secret-token', null, 'id.token.secret', 'access-secret');

        $row = $this->connection->fetchAssociative('SELECT * FROM `sw6oidc_session`');
        self::assertIsArray($row);
        $raw = implode("\n", array_map(static fn (mixed $value): string => \is_string($value) ? $value : '', $row));

        self::assertStringNotContainsString('ctx-secret-token', $raw);
        self::assertStringNotContainsString('id.token.secret', $raw);
        self::assertStringNotContainsString('access-secret', $raw);
        self::assertSame(hash('sha256', 'ctx-secret-token'), $row['session_key_hash']);
    }

    public function testSubAndSidAreScopedToTheProvider(): void
    {
        $this->registry->register($this->providerId, 'same-sub', 'same-sid', 'customer', $this->customerId, 'ctx-1');
        $otherProvider = Uuid::randomHex();

        self::assertSame([], $this->registry->resolve($otherProvider, 'same-sub'));
        self::assertSame([], $this->registry->resolveBySid($otherProvider, 'same-sid'));
    }

    public function testRemoveEndsOnlyThatSession(): void
    {
        $a = $this->registry->register($this->providerId, 'sub', 'sid-a', 'customer', $this->customerId, 'ctx-a');
        $b = $this->registry->register($this->providerId, 'sub', 'sid-b', 'customer', $this->customerId, 'ctx-b');

        $this->registry->remove($a);

        self::assertEquals([$b], $this->registry->resolve($this->providerId, 'sub'));
        self::assertSame([], $this->registry->resolveBySid($this->providerId, 'sid-a'));
    }

    public function testRemoveAllForUser(): void
    {
        $this->registry->register($this->providerId, 'sub', 'sid-a', 'admin', $this->customerId, 'jti-a');
        $this->registry->register($this->providerId, 'sub', 'sid-b', 'admin', $this->customerId, 'jti-b');

        self::assertSame(2, $this->registry->removeAllForUser('admin', $this->customerId));
        self::assertSame([], SqliteSessionRegistry::sessionsOf($this->registry, 'admin', $this->customerId));
    }

    public function testEmptySidIsStoredAsNull(): void
    {
        $session = $this->registry->register($this->providerId, 'sub', '', 'customer', $this->customerId, 'ctx');

        self::assertNull($session->sid);
        self::assertNull($this->registry->get($session->id)?->sid);
    }

    public function testExpiredEntriesAreInvisibleAndPruned(): void
    {
        $session = $this->registry->register($this->providerId, 'sub', null, 'customer', $this->customerId, 'ctx', ttlSeconds: 60);
        $this->connection->executeStatement('UPDATE `sw6oidc_session` SET `expires_at` = :past', ['past' => '2000-01-01 00:00:00.000']);

        self::assertNull($this->registry->get($session->id));
        self::assertSame([], $this->registry->resolve($this->providerId, 'sub'));
        self::assertSame(1, $this->registry->prune());
    }

    /**
     * R3-H5: an admin who keeps refreshing is still logged in on day 8; the
     * entry must stay targetable for back-channel logout as long as core has
     * a refresh token for that admin.
     */
    public function testAdminEntryLivesAsLongAsARefreshToken(): void
    {
        $adminId = Uuid::randomHex();
        $session = $this->registry->register($this->providerId, 'admin-sub', 'sid-1', 'admin', $adminId, 'jti');
        $this->age('8 days');
        $this->connection->insert('refresh_token', ['user_id' => Uuid::fromHexToBytes($adminId), 'expires_at' => $this->at('+6 days')]);

        self::assertSame(0, $this->registry->prune());
        self::assertSame([$session->id], array_map(static fn (Sw6OidcSession $s): string => $s->id, $this->registry->resolveBySid($this->providerId, 'sid-1')));

        $this->connection->executeStatement('UPDATE `refresh_token` SET `expires_at` = :past', ['past' => $this->at('-1 minute')]);

        self::assertSame(1, $this->registry->prune());
        self::assertSame([], $this->registry->resolveBySid($this->providerId, 'sid-1'));
    }

    public function testCustomerEntryLivesAsLongAsItsContextIsUsed(): void
    {
        $salesChannelId = Uuid::randomHex();
        $this->registry->register($this->providerId, 'sub', null, 'customer', $this->customerId, 'ctx', $salesChannelId);
        $this->age('40 days');
        $this->connection->insert('sales_channel_api_context', [
            'token' => 'ctx',
            'customer_id' => Uuid::fromHexToBytes($this->customerId),
            'sales_channel_id' => Uuid::fromHexToBytes($salesChannelId),
            'updated_at' => $this->at('-1 hour'),
        ]);

        self::assertSame(0, $this->registry->prune());
        self::assertCount(1, $this->registry->resolve($this->providerId, 'sub'));

        $this->connection->executeStatement('UPDATE `sales_channel_api_context` SET `updated_at` = :stale', ['stale' => $this->at('-2 days')]);

        self::assertSame(1, $this->registry->prune());
    }

    public function testFreshEntriesAreNeverPrunedForLiveness(): void
    {
        // Admin OIDC: registered at the callback, the refresh token only exists after the nonce exchange.
        $this->registry->register($this->providerId, 'sub', null, 'admin', Uuid::randomHex(), 'pending:x', ttlSeconds: 600);

        self::assertSame(0, $this->registry->prune());
    }

    public function testPendingAdminEntryIsActivatedWithTheJti(): void
    {
        $adminId = Uuid::randomHex();
        $pending = $this->registry->register($this->providerId, 'sub', null, 'admin', $adminId, 'pending:x', ttlSeconds: 600);

        $this->registry->activate($pending->id, 'jti-1');

        self::assertSame($pending->id, $this->registry->findBySessionKey('admin', $adminId, 'jti-1')?->id);
        self::assertNull($this->registry->findBySessionKey('admin', $adminId, 'pending:x'));
        self::assertSame($pending->id, $this->registry->findForUser('admin', $adminId, $pending->id)?->id);
        self::assertNull($this->registry->findForUser('admin', Uuid::randomHex(), $pending->id), 'the handle only works for its own account');
    }

    public function testUnknownEntriesResolveToNothing(): void
    {
        self::assertNull($this->registry->get('0123456789abcdef0123456789abcdef'));
        self::assertSame([], $this->registry->resolve($this->providerId, 'nobody'));
        self::assertSame([], SqliteSessionRegistry::sessionsOf($this->registry, 'admin', Uuid::randomHex()));
    }

    private function age(string $age): void
    {
        $this->connection->executeStatement('UPDATE `sw6oidc_session` SET `created_at` = :createdAt', ['createdAt' => $this->at('-' . $age)]);
    }

    private function at(string $modifier): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify($modifier)->format('Y-m-d H:i:s.v');
    }
}
