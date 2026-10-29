<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * The tables behind Administration role sync (R3-M11): an admin's ACL roles,
 * the subset role sync granted (`sw6oidc_managed_acl_role`), and the
 * superadmin revoke, which must not race. All ids are hex.
 */
class AdminRoleStore
{
    public function __construct(private readonly Connection $connection)
    {
    }

    /**
     * @return list<string>
     */
    public function roleIds(string $userId): array
    {
        return $this->ids('SELECT LOWER(HEX(`acl_role_id`)) FROM `acl_user_role` WHERE `user_id` = :userId', $userId);
    }

    /**
     * @return list<string>
     */
    public function managedRoleIds(string $userId): array
    {
        return $this->ids('SELECT LOWER(HEX(`acl_role_id`)) FROM `sw6oidc_managed_acl_role` WHERE `user_id` = :userId', $userId);
    }

    /**
     * @param list<string> $roleIds roles role sync granted (never the provider default)
     */
    public function rememberManaged(string $userId, array $roleIds, string $providerId): void
    {
        foreach ($roleIds as $roleId) {
            $this->connection->executeStatement(
                'INSERT IGNORE INTO `sw6oidc_managed_acl_role` (`user_id`, `acl_role_id`, `provider_id`, `created_at`) VALUES (:userId, :roleId, :providerId, :now)',
                [
                    'userId' => Uuid::fromHexToBytes($userId),
                    'roleId' => Uuid::fromHexToBytes($roleId),
                    'providerId' => Uuid::fromHexToBytes($providerId),
                    'now' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                ],
            );
        }
    }

    /**
     * @param list<string> $roleIds
     */
    public function forgetManaged(string $userId, array $roleIds): void
    {
        if ($roleIds === []) {
            return;
        }

        $this->connection->executeStatement(
            'DELETE FROM `sw6oidc_managed_acl_role` WHERE `user_id` = :userId AND `acl_role_id` IN (:roleIds)',
            ['userId' => Uuid::fromHexToBytes($userId), 'roleIds' => array_map(Uuid::fromHexToBytes(...), $roleIds)],
            ['roleIds' => ArrayParameterType::BINARY],
        );
    }

    /**
     * Runs $revoke unless the admin is the last active superadmin. The check
     * and the revoke share one transaction with the other superadmins' rows
     * locked, so two of the last superadmins logging in at once can't both
     * be revoked.
     *
     * @param callable(): mixed $revoke
     *
     * @return bool whether $revoke ran
     */
    public function revokeSuperadminUnlessLast(string $userId, callable $revoke): bool
    {
        return $this->connection->transactional(function (Connection $connection) use ($userId, $revoke): bool {
            $others = $connection->fetchFirstColumn(
                'SELECT `id` FROM `user` WHERE `admin` = 1 AND `active` = 1 AND `id` <> :id FOR UPDATE',
                ['id' => Uuid::fromHexToBytes($userId)],
            );

            if ($others === []) {
                return false;
            }

            $revoke();

            return true;
        });
    }

    /**
     * @return list<string>
     */
    private function ids(string $sql, string $userId): array
    {
        /** @var list<string> $ids */
        $ids = $this->connection->fetchFirstColumn($sql, ['userId' => Uuid::fromHexToBytes($userId)]);

        return $ids;
    }
}
