<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Security state moves from cache pools into tables, where `cache:clear`,
 * deploys and cache-pool evictions can't silently drop it:
 *
 *  - sw6oidc_session: the session registry (which local session an OIDC
 *    login created, looked up by provider+sid, provider+sub and account),
 *    kept for the real session lifetime. Session keys and tokens are stored
 *    encrypted, with a hash for lookups.
 *  - sw6oidc_one_time_token: single-use values (OAuth state, nonces, WebAuthn
 *    ceremonies, logout contexts, jti replay markers) with an explicit
 *    expiry; consumed with a locking read + delete.
 *  - sw6oidc_node_heartbeat: which app servers recently served the plugin,
 *    for the multi-node-without-Redis health warning.
 */
class Migration1790800006CreateStateTables extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800006;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS `sw6oidc_session` (
                `id` CHAR(32) NOT NULL,
                `provider_id` BINARY(16) NOT NULL,
                `sub` VARCHAR(255) NOT NULL,
                `sid` VARCHAR(255) NULL,
                `user_type` VARCHAR(16) NOT NULL,
                `user_id` BINARY(16) NOT NULL,
                `session_key` TEXT NOT NULL,
                `session_key_hash` CHAR(64) NOT NULL,
                `sales_channel_id` BINARY(16) NULL,
                `id_token` TEXT NULL,
                `idp_access_token` TEXT NULL,
                `idp_refresh_token` TEXT NULL,
                `created_at` DATETIME(3) NOT NULL,
                `expires_at` DATETIME(3) NOT NULL,
                PRIMARY KEY (`id`),
                KEY `idx.sw6oidc_session.provider_sid` (`provider_id`, `sid`),
                KEY `idx.sw6oidc_session.provider_sub` (`provider_id`, `sub`),
                KEY `idx.sw6oidc_session.user` (`user_type`, `user_id`),
                KEY `idx.sw6oidc_session.session_key_hash` (`session_key_hash`),
                KEY `idx.sw6oidc_session.expires_at` (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS `sw6oidc_one_time_token` (
                `key_hash` CHAR(64) NOT NULL,
                `value` MEDIUMTEXT NOT NULL,
                `expires_at` DATETIME(3) NOT NULL,
                PRIMARY KEY (`key_hash`),
                KEY `idx.sw6oidc_one_time_token.expires_at` (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS `sw6oidc_node_heartbeat` (
                `hostname` VARCHAR(255) NOT NULL,
                `last_seen_at` DATETIME(3) NOT NULL,
                PRIMARY KEY (`hostname`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
