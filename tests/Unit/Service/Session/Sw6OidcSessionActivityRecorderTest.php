<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Session;

use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemorySessionActivityRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(Sw6OidcSessionActivityRecorder::class)]
final class Sw6OidcSessionActivityRecorderTest extends TestCase
{
    private InMemorySessionActivityRepository $store;

    private Sw6OidcSessionActivityRecorder $recorder;

    protected function setUp(): void
    {
        $this->store = new InMemorySessionActivityRepository();
        $this->recorder = new Sw6OidcSessionActivityRecorder($this->store->mock(fn (string $class) => $this->createMock($class)), new NullLogger());
    }

    public function testLoginStoresRequestMetadataButNeverTheRawSessionKey(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_USER_AGENT' => 'Browser/1.0']);
        $session = new Sw6OidcSession('reg-1', 'p1', 'sub-1', 'sid-1', 'customer', 'c1', 'ctx-token');

        $this->recorder->recordLogin('customer', 'c1', 'oidc', 'ctx-token', $request, 'p1', $session);

        $row = array_values($this->store->rows)[0];
        self::assertSame('198.51.100.7', $row['ipAddress']);
        self::assertSame('Browser/1.0', $row['userAgent']);
        self::assertSame(['sub-1', 'sha256:' . hash('sha256', 'sid-1'), 'reg-1', 'p1'], [$row['sub'], $row['sid'], $row['registrySessionId'], $row['providerId']]);
        self::assertSame(hash('sha256', 'ctx-token'), $row['sessionKeyHash']);
        self::assertStringNotContainsString('ctx-token', (string) json_encode($row));
    }

    public function testIpCanBeStoredTruncated(): void
    {
        $recorder = new Sw6OidcSessionActivityRecorder($this->store->mock(fn (string $class) => $this->createMock($class)), new NullLogger(), null, true);

        $recorder->recordLogin('customer', 'c1', 'passkey', 'ctx-a', Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $recorder->recordLogin('customer', 'c1', 'passkey', 'ctx-b', Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '2001:db8:1:2:aaaa::1']));

        self::assertSame(['198.51.100.0', '2001:db8:1:2::'], array_column(array_values($this->store->rows), 'ipAddress'));
    }

    public function testLogoutClosesTheMatchingSessionOnly(): void
    {
        $this->login('ctx-a', null, '-2 minutes');
        $this->login('ctx-b', null, '-1 minute');

        $this->recorder->recordLogout('customer', 'c1', 'logout', 'ctx-a');

        self::assertSame(['ctx-a' => 'logout', 'ctx-b' => null], $this->reasons());
    }

    public function testLogoutMatchesByRegistrySessionId(): void
    {
        $this->login('ctx-a', 'reg-a');
        $this->login('ctx-b', 'reg-b');

        $this->recorder->recordLogout('customer', 'c1', 'backchannel', null, 'reg-b');

        self::assertSame(['ctx-a' => null, 'ctx-b' => 'backchannel'], $this->reasons());
    }

    public function testUnmatchedLogoutClosesNothing(): void
    {
        $this->login('ctx-old', null, '-2 minutes');
        $this->login('ctx-new', null, '-1 minute');

        $this->recorder->recordLogout('customer', 'c1', 'logout', 'refreshed-jti');
        // Guessing the newest row would close another device's session (N-M4).
        self::assertSame(['ctx-old' => null, 'ctx-new' => null], $this->reasons());
    }

    public function testLogoutOfAllSessionsClosesEveryOpenRowOfTheAccount(): void
    {
        $this->login('ctx-a');
        $this->login('ctx-b');

        $this->recorder->recordLogoutOfAllSessions('customer', 'c1', 'forced');

        self::assertSame(['ctx-a' => 'forced', 'ctx-b' => 'forced'], $this->reasons());
    }

    public function testLogoutOfAllSessionsClosesMoreThanOneBatch(): void
    {
        for ($i = 0; $i < 450; ++$i) {
            $this->store->rows['a' . $i] = ['id' => 'a' . $i, 'userType' => 'customer', 'userId' => 'c1', 'loggedOutAt' => null, 'loggedInAt' => new \DateTimeImmutable('-' . $i . ' minutes')];
        }

        $this->recorder->recordLogoutOfAllSessions('customer', 'c1', 'forced');

        // Not just the newest 200 (R3-L31).
        self::assertSame([], array_filter($this->store->rows, static fn (array $row): bool => $row['loggedOutAt'] === null));
    }

    public function testRepositoryFailuresNeverEscape(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('create')->willThrowException(new \RuntimeException('db down'));
        $repository->method('search')->willThrowException(new \RuntimeException('db down'));
        $recorder = new Sw6OidcSessionActivityRecorder($repository, new NullLogger());

        $recorder->recordLogin('admin', 'u1', 'passkey', 'jti', null);
        $recorder->recordLogout('admin', 'u1', 'logout', 'jti');
        $recorder->recordLogoutOfAllSessions('admin', 'u1', 'forced');

        $this->addToAssertionCount(1);
    }

    private function login(string $sessionKey, ?string $registryId = null, string $when = 'now'): void
    {
        $this->recorder->recordLogin('customer', 'c1', 'oidc', $sessionKey, null, 'p1', $registryId !== null ? new Sw6OidcSession($registryId, 'p1', 'sub', null, 'customer', 'c1', $sessionKey) : null);

        // Deterministic ordering for the "newest" fallback.
        $id = array_key_last($this->store->rows);
        $this->store->rows[$id]['loggedInAt'] = new \DateTimeImmutable($when);
    }

    /**
     * @return array<string, string|null> session key => logout reason
     */
    private function reasons(): array
    {
        $reasons = [];

        foreach ($this->store->rows as $row) {
            foreach (['ctx-a', 'ctx-b', 'ctx-old', 'ctx-new'] as $key) {
                if ($row['sessionKeyHash'] === hash('sha256', $key)) {
                    $reasons[$key] = $row['logoutReason'] ?? null;
                }
            }
        }

        return $reasons;
    }
}
