<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1758000001AddProviderTestStatus extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1758000001;
    }

    public function update(Connection $connection): void
    {
        // Idempotent: a restore with a stale `migration` table must not fail (R3-L38).
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (!\in_array('last_test_status', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` ADD COLUMN `last_test_status` VARCHAR(16) NULL AFTER `jwks_cache_ttl`');
        }

        if (!\in_array('last_test_at', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` ADD COLUMN `last_test_at` DATETIME(3) NULL AFTER `last_test_status`');
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
