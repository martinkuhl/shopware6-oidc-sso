<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Shopware\Core\DevOps\Environment\EnvironmentHelper;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * Upgrades stored provider secrets from the v1 envelope (one key for every
 * value, no associated data) to v2 (per-field key, AEAD with the field as
 * associated data). Idempotent; values that can't be decrypted with this
 * installation's APP_SECRET are left untouched (they have to be re-entered
 * anyway).
 */
class Migration1790800010ReencryptSecrets extends MigrationStep
{
    private const FIELDS = ['client_secret', 'health_alert_webhook_url'];

    public function getCreationTimestamp(): int
    {
        return 1790800010;
    }

    public function update(Connection $connection): void
    {
        $appSecret = (string) EnvironmentHelper::getVariable('APP_SECRET', '');

        if ($appSecret === '') {
            return;
        }

        $encryptor = new Sw6OidcEncryptor($appSecret);

        foreach (self::FIELDS as $field) {
            /** @var list<array{id: string, value: string}> $rows */
            $rows = $connection->fetchAllAssociative(
                sprintf('SELECT `id`, `%s` AS `value` FROM `sw6oidc_provider` WHERE `%s` LIKE :prefix', $field, $field),
                ['prefix' => 'sw6oidc\_v1:%'],
            );

            foreach ($rows as $row) {
                $plaintext = $encryptor->decryptOrNull($row['value']);

                if ($plaintext === null) {
                    continue;
                }

                $connection->update(
                    'sw6oidc_provider',
                    [$field => $encryptor->encrypt($plaintext, 'sw6oidc_provider.' . $field)],
                    ['id' => $row['id']],
                );
            }
        }
    }

    public function updateDestructive(Connection $connection): void
    {
        // No destructive changes.
    }
}
