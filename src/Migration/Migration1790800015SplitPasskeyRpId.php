<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * The Administration gets an RP ID of its own (`passkeyRpIdAdmin`, R3-M8).
 * An existing global `passkeyRpId` is copied there when it covers the host
 * of APP_URL, so admin passkeys keep working.
 */
class Migration1790800015SplitPasskeyRpId extends MigrationStep
{
    private const KEY_RP_ID = 'Sw6Oidc.config.passkeyRpId';
    private const KEY_RP_ID_ADMIN = 'Sw6Oidc.config.passkeyRpIdAdmin';

    public function getCreationTimestamp(): int
    {
        return 1790800015;
    }

    public function update(Connection $connection): void
    {
        $exists = $connection->fetchOne(
            'SELECT 1 FROM `system_config` WHERE `configuration_key` = :key AND `sales_channel_id` IS NULL',
            ['key' => self::KEY_RP_ID_ADMIN],
        );
        $value = $connection->fetchOne(
            'SELECT `configuration_value` FROM `system_config` WHERE `configuration_key` = :key AND `sales_channel_id` IS NULL',
            ['key' => self::KEY_RP_ID],
        );

        if ($exists !== false || !\is_string($value)) {
            return;
        }

        $rpId = json_decode($value, true)['_value'] ?? null;
        $appUrl = $_SERVER['APP_URL'] ?? $_ENV['APP_URL'] ?? getenv('APP_URL');
        $host = \is_string($appUrl) ? strtolower((string) parse_url($appUrl, PHP_URL_HOST)) : '';

        if (!\is_string($rpId) || $rpId === '' || $host === '' || ($host !== strtolower($rpId) && !str_ends_with($host, '.' . strtolower($rpId)))) {
            return;
        }

        $connection->insert('system_config', [
            'id' => Uuid::randomBytes(),
            'configuration_key' => self::KEY_RP_ID_ADMIN,
            'configuration_value' => json_encode(['_value' => $rpId], \JSON_THROW_ON_ERROR),
            'sales_channel_id' => null,
            'created_at' => (new \DateTimeImmutable())->format('Y-m-d H:i:s.v'),
        ]);
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
