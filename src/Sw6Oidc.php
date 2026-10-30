<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AdminProvisioningService;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use Shopware\Core\Framework\Plugin;
use Shopware\Core\Framework\Plugin\Context\UninstallContext;
use Symfony\Component\DependencyInjection\ContainerInterface;

class Sw6Oidc extends Plugin
{
    /** Dependent tables first (FK-safe order). */
    private const TABLES = [
        'sw6oidc_passkey_credential',
        'sw6oidc_user_provider',
        'sw6oidc_managed_acl_role',
        'sw6oidc_session_activity',
        'sw6oidc_session',
        'sw6oidc_one_time_token',
        'sw6oidc_node_heartbeat',
        'sw6oidc_access_control_rule',
        'sw6oidc_role_mapping',
        'sw6oidc_attribute_mapping',
        'sw6oidc_provider',
    ];

    public function uninstall(UninstallContext $uninstallContext): void
    {
        parent::uninstall($uninstallContext);

        if ($uninstallContext->keepUserData()) {
            return;
        }

        if (!$this->container instanceof ContainerInterface) {
            throw new \LogicException('The plugin container is not available during uninstall.');
        }

        /** @var Connection $connection */
        $connection = $this->container->get(Connection::class);

        foreach (self::TABLES as $table) {
            $connection->executeStatement(sprintf('DROP TABLE IF EXISTS `%s`', $table));
        }

        $connection->executeStatement('DELETE FROM `system_config` WHERE `configuration_key` LIKE \'Sw6Oidc.config.%\'');
        $connection->executeStatement('DELETE FROM `scheduled_task` WHERE `name` LIKE \'sw6oidc.%\'');

        $this->removeAclPrivileges($connection);
        $this->removeCustomFieldKeys($connection);
    }

    /**
     * Roles keep the plugin's privileges (`sw6oidc_provider:read`, …) in
     * their JSON list; they would point at entities that are gone (R8-L29).
     */
    private function removeAclPrivileges(Connection $connection): void
    {
        $roles = $connection->fetchAllKeyValue('SELECT `id`, `privileges` FROM `acl_role` WHERE `privileges` LIKE \'%sw6oidc%\'');

        foreach ($roles as $id => $privileges) {
            $list = json_decode((string) $privileges, true);

            if (!\is_array($list)) {
                continue;
            }

            $kept = array_values(array_filter($list, static fn (mixed $privilege): bool => !\is_string($privilege) || !str_starts_with($privilege, 'sw6oidc')));
            $connection->update('acl_role', ['privileges' => json_encode($kept, \JSON_THROW_ON_ERROR)], ['id' => $id]);
        }
    }

    /**
     * The keys the plugin writes into core entities' custom fields: avatar
     * import bookkeeping and the placeholder-address flag (R8-L29).
     */
    private function removeCustomFieldKeys(Connection $connection): void
    {
        $keys = [
            'user' => [AdminProvisioningService::AVATAR_URL_HASH_FIELD, AdminProvisioningService::AVATAR_MEDIA_ID_FIELD],
            'customer_address' => [CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD],
        ];

        foreach ($keys as $table => $fields) {
            foreach ($fields as $field) {
                $connection->executeStatement(sprintf(
                    'UPDATE `%s` SET `custom_fields` = JSON_REMOVE(`custom_fields`, :path) WHERE JSON_CONTAINS_PATH(`custom_fields`, \'one\', :path)',
                    $table,
                ), ['path' => '$.' . $field]);
            }
        }
    }
}
