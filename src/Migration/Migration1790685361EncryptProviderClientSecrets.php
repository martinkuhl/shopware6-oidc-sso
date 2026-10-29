<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Shopware\Core\DevOps\Environment\EnvironmentHelper;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Encrypts sw6oidc_provider.client_secret at rest (see Sw6OidcEncryptedField):
 * widens the column for the encrypted envelope, then encrypts every row that
 * isn't already "sw6oidc_v1:"-prefixed. Idempotent.
 *
 * If APP_SECRET isn't available in the migration's environment, rows stay
 * plaintext — they keep working (decrypt() passes plaintext through) and get
 * encrypted the next time the provider is saved.
 */
class Migration1790685361EncryptProviderClientSecrets extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790685361;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
            ALTER TABLE `sw6oidc_provider`
                MODIFY COLUMN `client_secret` VARCHAR(2048) NOT NULL
        SQL);

        $appSecret = (string) EnvironmentHelper::getVariable('APP_SECRET', '');

        if ($appSecret === '') {
            return;
        }

        $encryptor = new Sw6OidcEncryptor($appSecret);

        /** @var list<array{id: string, client_secret: string}> $rows */
        $rows = $connection->fetchAllAssociative(
            'SELECT `id`, `client_secret` FROM `sw6oidc_provider` WHERE `client_secret` NOT LIKE :prefix',
            // Any envelope version counts as already encrypted.
            ['prefix' => 'sw6oidc\_v%'],
        );

        foreach ($rows as $row) {
            $connection->update(
                'sw6oidc_provider',
                ['client_secret' => $encryptor->encrypt($row['client_secret'], 'sw6oidc_provider.client_secret')],
                ['id' => $row['id']],
            );
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
