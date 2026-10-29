<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Migration;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Shopware\Core\Framework\Migration\MigrationStep;

/**
 * RP-initiated logout used to guess Authelia's forward-auth logout (`?rd=`)
 * from the URL shape, which also matched Keycloak and Auth0 (R3-M3). The
 * style is now an explicit provider setting. Existing providers keep today's
 * behaviour, except for the recognisable endpoints of other IdPs, which the
 * old guess got wrong.
 */
class Migration1790800016AddProviderLogoutStyle extends MigrationStep
{
    /** Paths the old heuristic took for Authelia but that belong to standard OIDC IdPs. */
    private const KNOWN_STANDARD_PATHS = [
        '/protocol/openid-connect/logout',
        '/v2/logout',
        '/v1/logout',
        '/oauth2/v2.0/logout',
    ];

    public function getCreationTimestamp(): int
    {
        return 1790800016;
    }

    public function update(Connection $connection): void
    {
        $columns = array_map(strtolower(...), $connection->fetchFirstColumn('SHOW COLUMNS FROM `sw6oidc_provider`'));

        if (\in_array('logout_style', $columns, true)) {
            return;
        }

        $connection->executeStatement("ALTER TABLE `sw6oidc_provider` ADD COLUMN `logout_style` VARCHAR(32) NOT NULL DEFAULT 'standard' AFTER `end_session_endpoint`");

        foreach ($connection->fetchAllAssociative('SELECT `id`, `end_session_endpoint` FROM `sw6oidc_provider`') as $row) {
            if (\is_string($row['end_session_endpoint']) && self::wasTreatedAsAuthelia($row['end_session_endpoint'])) {
                $connection->executeStatement(
                    "UPDATE `sw6oidc_provider` SET `logout_style` = 'authelia_forward_auth' WHERE `id` = :id",
                    ['id' => $row['id']],
                    ['id' => ParameterType::BINARY],
                );
            }
        }
    }

    public function updateDestructive(Connection $connection): void
    {
    }

    /**
     * The old URL heuristic, minus the endpoints it misread.
     */
    public static function wasTreatedAsAuthelia(string $endSessionEndpoint): bool
    {
        $path = (string) (parse_url($endSessionEndpoint, PHP_URL_PATH) ?? '');

        if (!str_ends_with($path, '/logout') || str_contains($path, '/oauth2/') || str_contains($path, '/oidc/')) {
            return false;
        }

        foreach (self::KNOWN_STANDARD_PATHS as $standardPath) {
            if (str_ends_with($path, $standardPath)) {
                return false;
            }
        }

        return true;
    }
}
