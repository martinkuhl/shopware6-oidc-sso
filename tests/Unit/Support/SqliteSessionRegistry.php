<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Support;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Shopware\Core\Framework\Uuid\Uuid;
use Psr\Log\NullLogger;

/**
 * A real Sw6OidcSessionRegistry on an in-memory SQLite database (the
 * registry's SQL is portable), for unit tests that exercise session lookup
 * without a MySQL server.
 */
final class SqliteSessionRegistry
{
    public static function create(?Connection $connection = null, string $customerContextLifetime = 'P1D'): Sw6OidcSessionRegistry
    {
        return new Sw6OidcSessionRegistry($connection ?? self::connection(), new Sw6OidcEncryptor('unit-test-app-secret'), new NullLogger(), $customerContextLifetime);
    }

    /**
     * The live sessions of an account, oldest first — what the registry's
     * former resolveByUser() returned; production code never needed it.
     *
     * @return list<Sw6OidcSession>
     */
    public static function sessionsOf(Sw6OidcSessionRegistry $registry, string $userType, string $userId): array
    {
        $connection = (new \ReflectionProperty($registry, 'connection'))->getValue($registry);
        \assert($connection instanceof Connection);

        $ids = $connection->fetchFirstColumn(
            'SELECT `id` FROM `sw6oidc_session` WHERE `user_type` = :userType AND `user_id` = :userId ORDER BY `created_at` ASC',
            ['userType' => $userType, 'userId' => Uuid::fromHexToBytes($userId)],
        );

        return array_values(array_filter(array_map(static fn (mixed $id): ?Sw6OidcSession => $registry->get((string) $id), $ids)));
    }

    public static function connection(): Connection
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $connection->executeStatement(<<<'SQL'
            CREATE TABLE `sw6oidc_session` (
                `id` CHAR(32) NOT NULL PRIMARY KEY,
                `provider_id` BLOB NOT NULL,
                `sub` VARCHAR(255) NOT NULL,
                `sid` VARCHAR(255) NULL,
                `user_type` VARCHAR(16) NOT NULL,
                `user_id` BLOB NOT NULL,
                `session_key` TEXT NOT NULL,
                `session_key_hash` CHAR(64) NOT NULL,
                `sales_channel_id` BLOB NULL,
                `id_token` TEXT NULL,
                `idp_access_token` TEXT NULL,
                `idp_refresh_token` TEXT NULL,
                `created_at` DATETIME NOT NULL,
                `expires_at` DATETIME NOT NULL
            )
        SQL);
        // Core's session state the registry derives liveness from (R3-H5).
        $connection->executeStatement('CREATE TABLE `refresh_token` (`user_id` BLOB NOT NULL, `expires_at` DATETIME NOT NULL)');
        $connection->executeStatement('CREATE TABLE `sales_channel_api_context` (`token` VARCHAR(255) NOT NULL, `customer_id` BLOB NULL, `sales_channel_id` BLOB NULL, `updated_at` DATETIME NOT NULL)');

        return $connection;
    }
}
