<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * `button_label` / `button_color` were never read (`display_name` labels the
 * login buttons). The destructive step drops them (L3).
 */
class Migration1790800012DropProviderButtonColumns extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800012;
    }

    public function update(Connection $connection): void
    {
        // Destructive only.
    }

    public function updateDestructive(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        foreach (['button_label', 'button_color'] as $column) {
            if (\in_array($column, $columns, true)) {
                $connection->executeStatement(sprintf('ALTER TABLE `sw6oidc_provider` DROP COLUMN `%s`', $column));
            }
        }
    }
}
