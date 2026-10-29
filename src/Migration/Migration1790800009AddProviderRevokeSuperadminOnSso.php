<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * `revoke_superadmin_on_sso` (default off): role sync may also take the
 * superadmin flag away when the IdP groups no longer grant it — never from
 * the last active superadmin.
 */
class Migration1790800009AddProviderRevokeSuperadminOnSso extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800009;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (!\in_array('revoke_superadmin_on_sso', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` ADD COLUMN `revoke_superadmin_on_sso` TINYINT(1) NOT NULL DEFAULT 0');
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
