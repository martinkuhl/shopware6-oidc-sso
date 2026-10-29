<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Passkey credentials:
 *  - `disabled_at`: a credential whose signature counter went backwards (a
 *    possible clone) is disabled instead of silently failing forever.
 *  - `credential_id` widened: WebAuthn credential ids are up to 1023 bytes,
 *    stored base64 (up to 1364 characters) — 255 truncated long ids. Its
 *    uniqueness moves to `credential_id_hash` (sha256 of the base64 value):
 *    the wide column can't carry a unique index, and the case-insensitive
 *    collation would treat base64 ids differing only in case as equal.
 *  - index on `user_handle` (looked up on every registration and login).
 */
class Migration1790800007PasskeyCredentialHardening extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800007;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_passkey_credential`'));

        if (!\in_array('disabled_at', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` ADD COLUMN `disabled_at` DATETIME(3) NULL');
        }

        if (!\in_array('credential_id_hash', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` ADD COLUMN `credential_id_hash` CHAR(64) NULL AFTER `credential_id`');
        }

        $connection->executeStatement('UPDATE `sw6oidc_passkey_credential` SET `credential_id_hash` = SHA2(`credential_id`, 256) WHERE `credential_id_hash` IS NULL');
        $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` MODIFY `credential_id_hash` CHAR(64) NOT NULL');

        $indexes = array_map(
            strtolower(...),
            $connection->fetchFirstColumn(
                'SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \'sw6oidc_passkey_credential\'',
            ),
        );

        if (!\in_array('uniq.sw6oidc_passkey_credential.credential_id_hash', $indexes, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` ADD UNIQUE KEY `uniq.sw6oidc_passkey_credential.credential_id_hash` (`credential_id_hash`)');
        }

        if (\in_array('uniq.sw6oidc_passkey_credential.credential_id', $indexes, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` DROP INDEX `uniq.sw6oidc_passkey_credential.credential_id`');
        }

        $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` MODIFY `credential_id` VARCHAR(1400) NOT NULL');

        if (!\in_array('idx.sw6oidc_passkey_credential.user_handle', $indexes, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_passkey_credential` ADD INDEX `idx.sw6oidc_passkey_credential.user_handle` (`user_handle`)');
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
