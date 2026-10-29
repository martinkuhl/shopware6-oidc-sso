<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * `claim_encoding` hasn't been read since `base64_claims` replaced it (M10,
 * Migration1790800011 carried its value over). The destructive step drops it
 * (R3-L43); until then its column default keeps inserts working.
 */
class Migration1790800020DropProviderClaimEncoding extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800020;
    }

    public function update(Connection $connection): void
    {
        // Destructive only.
    }

    public function updateDestructive(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (\in_array('claim_encoding', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` DROP COLUMN `claim_encoding`');
        }
    }
}
