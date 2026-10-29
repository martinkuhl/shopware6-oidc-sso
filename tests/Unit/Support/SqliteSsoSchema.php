<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Support;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\ParameterType;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * The tables the SSO-only invariant and the provider write guards read
 * (providers, admins, bindings), on an in-memory SQLite database. Ids are
 * hex in the helpers and binary in the tables, like in MySQL.
 */
final class SqliteSsoSchema
{
    public readonly Connection $connection;

    public function __construct()
    {
        $this->connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $this->connection->executeStatement(<<<'SQL'
            CREATE TABLE `sw6oidc_provider` (
                `id` BLOB NOT NULL PRIMARY KEY,
                `is_active` INTEGER NOT NULL DEFAULT 1,
                `login_type` VARCHAR(16) NOT NULL DEFAULT 'both',
                `disable_non_oidc_admin_login` INTEGER NOT NULL DEFAULT 0,
                `disable_non_oidc_customer_login` INTEGER NOT NULL DEFAULT 0,
                `show_admin_link` INTEGER NOT NULL DEFAULT 1,
                `show_customer_link` INTEGER NOT NULL DEFAULT 1,
                `public_client` INTEGER NOT NULL DEFAULT 0,
                `client_secret` VARCHAR(2048) NULL,
                `access_token_endpoint` VARCHAR(1024) NULL,
                `revocation_endpoint` VARCHAR(1024) NULL,
                `user_info_endpoint` VARCHAR(1024) NULL,
                `well_known_config_url` VARCHAR(1024) NULL,
                `require_email_verified` INTEGER NOT NULL DEFAULT 1,
                `issuer` VARCHAR(1024) NULL
            )
        SQL);
        $this->connection->executeStatement('CREATE TABLE `user` (`id` BLOB NOT NULL PRIMARY KEY, `active` INTEGER NOT NULL DEFAULT 1)');
        $this->connection->executeStatement(<<<'SQL'
            CREATE TABLE `sw6oidc_attribute_mapping` (
                `id` BLOB NOT NULL PRIMARY KEY,
                `provider_id` BLOB NOT NULL,
                `attribute_type` VARCHAR(64) NOT NULL,
                `attribute_name` VARCHAR(255) NOT NULL,
                `transform_function` VARCHAR(32) NULL,
                `transform_params` TEXT NULL
            )
        SQL);
        $this->connection->executeStatement(<<<'SQL'
            CREATE TABLE `sw6oidc_user_provider` (
                `id` BLOB NOT NULL PRIMARY KEY,
                `provider_id` BLOB NOT NULL,
                `user_type` VARCHAR(16) NOT NULL,
                `user_id` BLOB NOT NULL,
                `issuer` VARCHAR(2048) NULL,
                `issuer_hash` CHAR(64) NULL
            )
        SQL);
    }

    /**
     * @param array<string, mixed> $columns
     */
    public function provider(array $columns = []): string
    {
        $id = Uuid::randomHex();
        $this->connection->insert('sw6oidc_provider', ['id' => Uuid::fromHexToBytes($id), 'client_secret' => 'sw6oidc_v2:stored', ...$columns], ['id' => ParameterType::BINARY]);

        return $id;
    }

    /**
     * @param array<string, mixed> $columns
     */
    public function attributeMapping(string $providerId, array $columns): string
    {
        $id = Uuid::randomHex();
        $this->connection->insert(
            'sw6oidc_attribute_mapping',
            ['id' => Uuid::fromHexToBytes($id), 'provider_id' => Uuid::fromHexToBytes($providerId), ...$columns],
            ['id' => ParameterType::BINARY, 'provider_id' => ParameterType::BINARY],
        );

        return $id;
    }

    public function admin(bool $active = true): string
    {
        $id = Uuid::randomHex();
        $this->connection->insert('user', ['id' => Uuid::fromHexToBytes($id), 'active' => (int) $active], ['id' => ParameterType::BINARY]);

        return $id;
    }

    public function bind(string $providerId, string $userId, string $userType = 'admin', string $issuer = 'https://idp.example'): void
    {
        $this->connection->insert('sw6oidc_user_provider', [
            'id' => Uuid::randomBytes(),
            'provider_id' => Uuid::fromHexToBytes($providerId),
            'user_type' => $userType,
            'user_id' => Uuid::fromHexToBytes($userId),
            'issuer' => $issuer,
            'issuer_hash' => hash('sha256', $issuer),
        ], ['id' => ParameterType::BINARY, 'provider_id' => ParameterType::BINARY, 'user_id' => ParameterType::BINARY]);
    }
}
