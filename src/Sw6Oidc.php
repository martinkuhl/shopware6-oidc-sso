<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc;

use Doctrine\DBAL\Connection;
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
    }
}
