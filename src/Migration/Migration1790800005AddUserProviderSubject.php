<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Binds accounts to the IdP subject (`iss` + `sub`) instead of the email
 * claim. Existing bindings keep a NULL subject and are backfilled on their
 * next login through the same provider with a verified email.
 *
 * Also adds the two provider policies that govern that lookup:
 * `require_email_verified` (default on) and `link_existing_accounts`
 * (default off — pre-existing accounts are only linked explicitly).
 */
class Migration1790800005AddUserProviderSubject extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800005;
    }

    public function update(Connection $connection): void
    {
        $bindingColumns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_user_provider`'));

        if (!\in_array('issuer', $bindingColumns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_user_provider` ADD COLUMN `issuer` VARCHAR(2048) NULL AFTER `provider_id`');
        }

        if (!\in_array('sub', $bindingColumns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_user_provider` ADD COLUMN `sub` VARCHAR(255) NULL AFTER `issuer`');
        }

        $indexes = array_map(
            strtolower(...),
            $connection->fetchFirstColumn(
                'SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \'sw6oidc_user_provider\'',
            ),
        );

        // One IdP subject owns at most one account per user type; a provider
        // serving both login types may bind the same subject to an admin and
        // a customer. MySQL unique indexes allow many NULLs (legacy rows).
        if (!\in_array('uniq.sw6oidc_user_provider.subject', $indexes, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_user_provider` ADD UNIQUE KEY `uniq.sw6oidc_user_provider.subject` (`provider_id`, `user_type`, `sub`)');
        }

        $providerColumns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        $columns = [
            'require_email_verified' => 'TINYINT(1) NOT NULL DEFAULT 1',
            'link_existing_accounts' => 'TINYINT(1) NOT NULL DEFAULT 0',
        ];

        foreach ($columns as $name => $definition) {
            if (!\in_array($name, $providerColumns, true)) {
                $connection->executeStatement(sprintf('ALTER TABLE `sw6oidc_provider` ADD COLUMN `%s` %s', $name, $definition));
            }
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
