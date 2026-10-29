<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Api;

use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use MartinKuhl\Sw6Oidc\Controller\Api\SessionActivityController;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemorySessionActivityRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

#[CoversClass(SessionActivityController::class)]
final class SessionActivityControllerTest extends TestCase
{
    private InMemorySessionActivityRepository $store;

    private Sw6OidcSessionActivityRecorder $recorder;

    private Sw6OidcSessionRegistry $registry;

    private Sw6OidcSessionDestructionService&MockObject $destruction;

    protected function setUp(): void
    {
        $this->store = new InMemorySessionActivityRepository();
        $this->recorder = new Sw6OidcSessionActivityRecorder($this->store->mock(fn (string $class) => $this->createMock($class)), new NullLogger());
        $this->registry = SqliteSessionRegistry::create();
        $this->destruction = $this->createMock(Sw6OidcSessionDestructionService::class);
    }

    public function testRegisteredCustomerSessionIsEndedExactly(): void
    {
        $session = $this->registry->register('a1000000000000000000000000000001', 'sub', 'sid', 'customer', 'c1000000000000000000000000000001', 'ctx-a', '5c000000000000000000000000000001');
        $this->recorder->recordLogin('customer', 'c1000000000000000000000000000001', 'oidc', 'ctx-a', null, 'a1000000000000000000000000000001', $session);
        $this->recorder->recordLogin('customer', 'c1000000000000000000000000000001', 'passkey', 'ctx-b', null);

        $this->destruction->expects(self::once())->method('destroy')->with($session);
        $this->destruction->expects(self::never())->method('destroyAllForUser');

        $body = $this->forceLogout($this->activityIdFor('ctx-a'));

        self::assertSame(['alreadyLoggedOut' => false, 'endedAllSessions' => false], $body);
        self::assertNull($this->registry->get($session->id));
        self::assertSame(['forced', null], $this->reasons());
    }

    public function testPasskeySessionEndsAllSessionsOfTheAccount(): void
    {
        $this->recorder->recordLogin('customer', 'c1000000000000000000000000000001', 'passkey', 'ctx-a', null);
        $this->recorder->recordLogin('customer', 'c1000000000000000000000000000001', 'oidc', 'ctx-b', null);

        $this->destruction->expects(self::once())->method('destroyAllForUser')->with('customer', 'c1000000000000000000000000000001');

        self::assertTrue($this->forceLogout($this->activityIdFor('ctx-a'))['endedAllSessions']);
        self::assertSame(['forced', 'forced'], $this->reasons());
    }

    public function testAdminAlwaysEndsAllSessionsAndClearsTheirRegistryEntries(): void
    {
        $session = $this->registry->register('a1000000000000000000000000000001', 'sub', 'sid', 'admin', 'e1000000000000000000000000000001', 'jti-a');
        $this->recorder->recordLogin('admin', 'e1000000000000000000000000000001', 'oidc', 'jti-a', null, 'a1000000000000000000000000000001', $session);

        $this->destruction->expects(self::once())->method('destroyAllForUser')->with('admin', 'e1000000000000000000000000000001');

        self::assertTrue($this->forceLogout($this->activityIdFor('jti-a'))['endedAllSessions']);
        self::assertSame([], SqliteSessionRegistry::sessionsOf($this->registry, 'admin', 'e1000000000000000000000000000001'));
    }

    public function testOnlyASuperadminMayEndAnAdministratorsSessions(): void
    {
        $this->recorder->recordLogin('admin', 'e1000000000000000000000000000001', 'oidc', 'jti-a', null);
        $this->destruction->expects(self::never())->method(self::anything());

        $response = $this->controller()->forceLogout($this->activityIdFor('jti-a'), new Context(new AdminApiSource('f1000000000000000000000000000001')));

        // A role with force_logout alone can't end a superadmin's sessions (R3-L37).
        self::assertSame(403, $response->getStatusCode());
    }

    public function testClosedOrUnknownActivity(): void
    {
        $this->recorder->recordLogin('customer', 'c1000000000000000000000000000001', 'passkey', 'ctx-a', null);
        $this->recorder->recordLogout('customer', 'c1000000000000000000000000000001', 'logout', 'ctx-a');
        $this->destruction->expects(self::never())->method(self::anything());

        self::assertTrue($this->forceLogout($this->activityIdFor('ctx-a'))['alreadyLoggedOut']);
        self::assertSame(404, $this->controller()->forceLogout('0190a1b2c3d4e5f60718293a4b5c6d7e', Context::createDefaultContext())->getStatusCode());
        self::assertSame(404, $this->controller()->forceLogout('not-a-uuid', Context::createDefaultContext())->getStatusCode());
    }

    /**
     * @return array<string, mixed>
     */
    private function forceLogout(string $activityId, ?Context $context = null): array
    {
        return json_decode((string) $this->controller()->forceLogout($activityId, $context ?? Context::createDefaultContext())->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }

    private function controller(): SessionActivityController
    {
        return new SessionActivityController($this->recorder, $this->registry, $this->destruction, new NullLogger(), 'P1W', 'P1D');
    }

    private function activityIdFor(string $sessionKey): string
    {
        foreach ($this->store->rows as $id => $row) {
            if ($row['sessionKeyHash'] === hash('sha256', $sessionKey)) {
                return (string) $id;
            }
        }

        self::fail('no activity for ' . $sessionKey);
    }

    /**
     * @return list<string|null> logout reasons in insertion order
     */
    private function reasons(): array
    {
        return array_values(array_map(static fn (array $row): ?string => $row['logoutReason'] ?? null, $this->store->rows));
    }

    public function testSettingsReportSessionLifetimesInSeconds(): void
    {
        $controller = new SessionActivityController($this->recorder, $this->registry, $this->destruction, new NullLogger(), 'PT10M', 'P1D');

        self::assertSame(
            ['sessionLifetimeSeconds' => ['admin' => 600, 'customer' => 86400]],
            json_decode((string) $controller->settings()->getContent(), true),
        );
    }
}
