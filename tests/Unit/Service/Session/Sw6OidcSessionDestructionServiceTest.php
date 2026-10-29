<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Session;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;

#[CoversClass(Sw6OidcSessionDestructionService::class)]
final class Sw6OidcSessionDestructionServiceTest extends TestCase
{
    public function testCustomerSessionDeletesExactlyThatContextToken(): void
    {
        $persister = $this->createMock(SalesChannelContextPersister::class);
        $persister->expects(self::once())->method('delete')->with('ctx-token', 'sc-1', 'cust-1');

        $refreshTokens = $this->createMock(RefreshTokenRepository::class);
        $refreshTokens->expects(self::never())->method('revokeRefreshTokensForUser');

        $connection = $this->createMock(Connection::class);
        $connection->method('fetchOne')->willReturn(1);
        $connection->expects(self::never())->method('executeStatement');

        (new Sw6OidcSessionDestructionService($persister, $refreshTokens, $connection, new NullLogger()))
            ->destroy($this->session('customer', 'cust-1', 'ctx-token', 'sc-1'));
    }

    public function testRotatedCustomerTokenEndsAllOfTheCustomersSessions(): void
    {
        $persister = $this->createMock(SalesChannelContextPersister::class);
        $persister->expects(self::never())->method('delete');
        $persister->expects(self::once())->method('revokeAllCustomerTokens')->with('cust-1');

        $connection = $this->createMock(Connection::class);
        // Core replaced the context token since the login (R3-L30).
        $connection->method('fetchOne')->willReturn(false);

        (new Sw6OidcSessionDestructionService($persister, $this->createMock(RefreshTokenRepository::class), $connection, new NullLogger()))
            ->destroy($this->session('customer', 'cust-1', 'ctx-token', 'sc-1'));
    }

    public function testAdminSessionRevokesRefreshTokensAndInvalidatesIssuedAccessTokens(): void
    {
        $userId = Uuid::randomHex();

        $persister = $this->createMock(SalesChannelContextPersister::class);
        $persister->expects(self::never())->method('delete');

        $refreshTokens = $this->createMock(RefreshTokenRepository::class);
        $refreshTokens->expects(self::once())->method('revokeRefreshTokensForUser')->with($userId);

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('executeStatement')->with(
            self::stringContains('`last_updated_password_at`'),
            self::callback(static fn (array $params): bool => $params['id'] === Uuid::fromHexToBytes($userId) && \is_string($params['now'])),
        );

        (new Sw6OidcSessionDestructionService($persister, $refreshTokens, $connection, new NullLogger()))
            ->destroy($this->session('admin', $userId, 'jti-1', null));
    }

    private function session(string $userType, string $userId, string $sessionKey, ?string $salesChannelId): Sw6OidcSession
    {
        return new Sw6OidcSession('id', 'p1', 'sub', 'sid', $userType, $userId, $sessionKey, $salesChannelId);
    }
}
