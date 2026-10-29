<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * The account binding becomes a real identity key (R3-M9, R3-M14):
 *
 * - `sub` and `issuer` compare byte-exactly (`utf8mb4_bin`): under the old
 *   case- and accent-insensitive collation `René`, `rene` and `RENE` were
 *   one subject;
 * - the issuer takes part in the key (`issuer_hash`, sha256 of `issuer`,
 *   which is too long for an index); legacy rows get their provider's issuer;
 * - `binding_scope`: the sales channel a channel-bound customer belongs to,
 *   else 16 zero bytes ("global"; a non-null sentinel, because a unique key
 *   treats NULLs as distinct). One IdP subject can own one customer account
 *   per sales channel when Shopware binds customers to sales channels.
 *
 * Unique key: (provider, user type, issuer, subject, scope); each account
 * still has at most one binding.
 */
class Migration1790800017BindingIdentityKey extends MigrationStep
{
    private const OLD_SUBJECT_KEY = 'uniq.sw6oidc_user_provider.subject';
    private const SUBJECT_KEY = 'uniq.sw6oidc_user_provider.identity';

    public function getCreationTimestamp(): int
    {
        return 1790800017;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_user_provider`'));

        if (!\in_array('issuer_hash', $columns, true)) {
            $connection->executeStatement(
                'ALTER TABLE `sw6oidc_user_provider`
                    MODIFY COLUMN `issuer` VARCHAR(2048) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
                    MODIFY COLUMN `sub` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
                    ADD COLUMN `issuer_hash` CHAR(64) NULL AFTER `issuer`',
            );
        }

        if (!\in_array('binding_scope', $columns, true)) {
            $connection->executeStatement(
                'ALTER TABLE `sw6oidc_user_provider`
                    ADD COLUMN `binding_scope` BINARY(16) NOT NULL DEFAULT 0x00000000000000000000000000000000 AFTER `sub`',
            );
        }

        // Legacy rows: the provider's current issuer.
        $connection->executeStatement(
            'UPDATE `sw6oidc_user_provider` binding
             INNER JOIN `sw6oidc_provider` provider ON provider.`id` = binding.`provider_id`
             SET binding.`issuer` = provider.`issuer`
             WHERE (binding.`issuer` IS NULL OR binding.`issuer` = \'\') AND provider.`issuer` IS NOT NULL AND provider.`issuer` <> \'\'',
        );
        $connection->executeStatement(
            'UPDATE `sw6oidc_user_provider` SET `issuer_hash` = SHA2(`issuer`, 256) WHERE `issuer` IS NOT NULL AND `issuer_hash` IS NULL',
        );

        // Channel-bound customers are bound in their channel.
        $connection->executeStatement(
            'UPDATE `sw6oidc_user_provider` binding
             INNER JOIN `customer` ON customer.`id` = binding.`user_id`
             SET binding.`binding_scope` = customer.`bound_sales_channel_id`
             WHERE binding.`user_type` = \'customer\' AND customer.`bound_sales_channel_id` IS NOT NULL',
        );

        $indexes = array_map(
            strtolower(...),
            $connection->fetchFirstColumn(
                'SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = \'sw6oidc_user_provider\'',
            ),
        );

        if (\in_array(self::OLD_SUBJECT_KEY, $indexes, true)) {
            $connection->executeStatement(\sprintf('ALTER TABLE `sw6oidc_user_provider` DROP INDEX `%s`', self::OLD_SUBJECT_KEY));
        }

        if (!\in_array(self::SUBJECT_KEY, $indexes, true)) {
            $connection->executeStatement(\sprintf(
                'ALTER TABLE `sw6oidc_user_provider` ADD UNIQUE KEY `%s` (`provider_id`, `user_type`, `issuer_hash`, `sub`, `binding_scope`)',
                self::SUBJECT_KEY,
            ));
        }
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
