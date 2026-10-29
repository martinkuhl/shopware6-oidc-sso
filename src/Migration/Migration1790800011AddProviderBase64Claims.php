<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * `base64_claims` (JSON list of claim names) replaces `claim_encoding =
 * base64`, which decoded *every* string claim and so corrupted plain ones
 * (M10). Providers that had base64 on get `["*"]` (all claims, the old
 * behaviour) — narrow it to the claims that are actually encoded.
 * `claim_encoding` is no longer read and is left in place for downgrades.
 */
class Migration1790800011AddProviderBase64Claims extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790800011;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (!\in_array('base64_claims', $columns, true)) {
            $connection->executeStatement('ALTER TABLE `sw6oidc_provider` ADD COLUMN `base64_claims` JSON NULL');
        }

        $connection->executeStatement(
            'UPDATE `sw6oidc_provider` SET `base64_claims` = :all WHERE `claim_encoding` = :base64 AND `base64_claims` IS NULL',
            ['all' => '["*"]', 'base64' => 'base64'],
        );
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
