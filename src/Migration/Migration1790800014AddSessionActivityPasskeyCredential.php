<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Remembers which passkey (credential_id_hash) logged a session in, so
 * deleting that passkey can end exactly those sessions (R3-M6).
 */
class Migration1790800014AddSessionActivityPasskeyCredential extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800014;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_session_activity`'));

        if (!\in_array('passkey_credential_hash', $columns, true)) {
            $connection->executeStatement(
                'ALTER TABLE `sw6oidc_session_activity`
                    ADD COLUMN `passkey_credential_hash` CHAR(64) NULL AFTER `registry_session_id`,
                    ADD INDEX `idx.sw6oidc_session_activity.passkey_credential_hash` (`passkey_credential_hash`)',
            );
        }
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
