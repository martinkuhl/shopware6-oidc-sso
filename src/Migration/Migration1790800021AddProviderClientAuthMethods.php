<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * How a confidential client authenticates at the token and the revocation
 * endpoint (`client_secret_basic` or `client_secret_post`). IdPs such as
 * Authelia register both per client and refuse any other method. Existing
 * providers keep HTTP Basic, the only method used so far.
 */
class Migration1790800021AddProviderClientAuthMethods extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800021;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (!\in_array('token_endpoint_auth_method', $columns, true)) {
            $connection->executeStatement(
                "ALTER TABLE `sw6oidc_provider` ADD COLUMN `token_endpoint_auth_method` VARCHAR(32) NOT NULL DEFAULT 'client_secret_basic' AFTER `access_token_endpoint`",
            );
        }

        if (!\in_array('revocation_endpoint_auth_method', $columns, true)) {
            $connection->executeStatement(
                "ALTER TABLE `sw6oidc_provider` ADD COLUMN `revocation_endpoint_auth_method` VARCHAR(32) NOT NULL DEFAULT 'client_secret_basic' AFTER `revocation_endpoint`",
            );
        }
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
