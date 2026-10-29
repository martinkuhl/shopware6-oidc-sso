<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * `frontchannel_admin_logout` (default off): whether an anonymous
 * front-channel logout request may end an Administration user's sessions.
 * Admin sessions can only be ended all at once, and a front-channel request
 * carries nothing but `iss` + `sid`, so by default it only ends customer
 * sessions; back-channel logout (signed) always applies to admins.
 */
class Migration1790800008AddProviderFrontchannelAdminLogout extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800008;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (!\in_array('frontchannel_admin_logout', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` ADD COLUMN `frontchannel_admin_logout` TINYINT(1) NOT NULL DEFAULT 0');
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
