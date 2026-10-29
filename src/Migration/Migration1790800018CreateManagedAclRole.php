<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Which Administration roles role sync granted (R3-M11): sync adds and
 * removes only these, so roles granted by hand in Shopware survive every
 * login. Existing installs are seeded with the bound admins' current roles
 * that a mapping row of their provider grants — the plugin can't tell those
 * apart from manual grants after the fact.
 */
class Migration1790800018CreateManagedAclRole extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800018;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS `sw6oidc_managed_acl_role` (
                `user_id` BINARY(16) NOT NULL,
                `acl_role_id` BINARY(16) NOT NULL,
                `provider_id` BINARY(16) NOT NULL,
                `created_at` DATETIME(3) NOT NULL,
                PRIMARY KEY (`user_id`, `acl_role_id`),
                CONSTRAINT `fk.sw6oidc_managed_acl_role.user_id` FOREIGN KEY (`user_id`)
                    REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT `fk.sw6oidc_managed_acl_role.acl_role_id` FOREIGN KEY (`acl_role_id`)
                    REFERENCES `acl_role` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT `fk.sw6oidc_managed_acl_role.provider_id` FOREIGN KEY (`provider_id`)
                    REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $connection->executeStatement(<<<'SQL'
            INSERT IGNORE INTO `sw6oidc_managed_acl_role` (`user_id`, `acl_role_id`, `provider_id`, `created_at`)
            SELECT DISTINCT user_role.`user_id`, user_role.`acl_role_id`, binding.`provider_id`, UTC_TIMESTAMP(3)
            FROM `acl_user_role` user_role
            INNER JOIN `sw6oidc_user_provider` binding ON binding.`user_id` = user_role.`user_id` AND binding.`user_type` = 'admin'
            INNER JOIN `sw6oidc_role_mapping` mapping ON mapping.`provider_id` = binding.`provider_id`
                AND mapping.`mapping_type` = 'admin_role'
                AND mapping.`acl_role_id` = user_role.`acl_role_id`
        SQL);
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
