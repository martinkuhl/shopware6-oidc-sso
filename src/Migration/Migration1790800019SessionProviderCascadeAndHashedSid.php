<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * - `sw6oidc_session` rows go with their provider (R3-L34): before, a deleted
 *   provider's encrypted IdP tokens stayed until the registry's hard bound.
 *   Orphans are removed first so the constraint can be added.
 * - `sw6oidc_session_activity.sid` keeps only `sha256:<hex>` (R3-L40): a
 *   front-channel `sid` ends the IdP session, and nothing reads it back.
 */
class Migration1790800019SessionProviderCascadeAndHashedSid extends MigrationStep
{
    private const FK_NAME = 'fk.sw6oidc_session.provider_id';

    public function getCreationTimestamp(): int
    {
        return 1790800019;
    }

    public function update(Connection $connection): void
    {
        $hasForeignKey = $connection->fetchOne(
            'SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
             WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = \'sw6oidc_session\' AND CONSTRAINT_NAME = :name',
            ['name' => self::FK_NAME],
        ) !== false;

        if (!$hasForeignKey) {
            $connection->executeStatement(
                'DELETE `session` FROM `sw6oidc_session` `session`
                 LEFT JOIN `sw6oidc_provider` `provider` ON `provider`.`id` = `session`.`provider_id`
                 WHERE `provider`.`id` IS NULL',
            );

            $connection->executeStatement(sprintf(
                'ALTER TABLE `sw6oidc_session` ADD CONSTRAINT `%s` FOREIGN KEY (`provider_id`)
                 REFERENCES `sw6oidc_provider` (`id`) ON DELETE CASCADE ON UPDATE CASCADE',
                self::FK_NAME,
            ));
        }

        // The prefix marks hashed values, so a re-run never hashes twice.
        $connection->executeStatement(
            'UPDATE `sw6oidc_session_activity`
             SET `sid` = CONCAT(\'sha256:\', SHA2(`sid`, 256))
             WHERE `sid` IS NOT NULL AND `sid` NOT LIKE \'sha256:%\'',
        );
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
