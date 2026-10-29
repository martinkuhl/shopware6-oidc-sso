<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Public clients have no client secret, so `client_secret` becomes nullable
 * and the empty placeholder of existing public clients becomes NULL (R3-M23).
 * The provider write guard requires a secret for confidential clients.
 */
class Migration1790800013MakeClientSecretOptional extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800013;
    }

    public function update(Connection $connection): void
    {
        $nullable = $connection->fetchOne(
            'SELECT IS_NULLABLE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \'sw6oidc_provider\' AND COLUMN_NAME = \'client_secret\'',
        );

        if ($nullable === 'NO') {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` MODIFY COLUMN `client_secret` VARCHAR(2048) NULL');
        }

        $connection->executeStatement('UPDATE `sw6oidc_provider` SET `client_secret` = NULL WHERE `client_secret` = \'\'');
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
