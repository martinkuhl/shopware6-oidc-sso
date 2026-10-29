<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * The one SSO-only invariant (R3-H7): whenever Administration password
 * login is effectively off, at least one *active* admin is bound to an
 * *active, admin-serving* provider. Every write that can change the answer
 * asks this class about its result, not about its payload: provider inserts,
 * updates and deletes (whatever field they touch: the flag, `is_active` or
 * `login_type`), user deactivation and deletion, and unlinking a binding.
 *
 * A binding only counts while it belongs to the provider's current issuer
 * (R3-M9): after an issuer change without re-binding, those accounts can't
 * log in through SSO any more.
 *
 * Queries run on raw tables because the callers run inside the DAL write
 * (PreWriteValidationEvent). All ids are hex.
 */
class SsoOnlyInvariant
{
    private const FLAG_COLUMNS = [
        LoginType::Admin->value => 'disable_non_oidc_admin_login',
        LoginType::Customer->value => 'disable_non_oidc_customer_login',
    ];

    private const SHOW_COLUMNS = [
        LoginType::Admin->value => 'show_admin_link',
        LoginType::Customer->value => 'show_customer_link',
    ];

    public function __construct(
        private readonly Connection $connection,
        private readonly bool $breakGlassAllowPasswordLogin = false,
    ) {
    }

    /**
     * Whether password login of this type is off, the same rule as
     * PasswordLoginPolicy, with pending provider changes applied.
     *
     * @param array<string, array<string, mixed>|null> $providerChanges provider id => stored columns to
     *                                                                   override, or null for a deleted provider
     */
    public function passwordLoginDisabled(string $loginType, array $providerChanges = []): bool
    {
        if ($this->breakGlassAllowPasswordLogin) {
            return false;
        }

        foreach ($this->servingProviders($loginType, $providerChanges) as $provider) {
            if ((bool) $provider[self::FLAG_COLUMNS[$loginType]]) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an active, admin-serving provider shows its SSO button for
     * this login type after the pending changes.
     *
     * @param array<string, array<string, mixed>|null> $providerChanges
     */
    public function loginButtonVisible(string $loginType, array $providerChanges = []): bool
    {
        foreach ($this->servingProviders($loginType, $providerChanges) as $provider) {
            if ((bool) $provider[self::SHOW_COLUMNS[$loginType]]) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether some active admin can still log in through SSO after the
     * pending changes.
     *
     * @param array<string, array<string, mixed>|null> $providerChanges
     * @param list<string>                             $removedUserIds    admins about to be deleted or deactivated
     * @param list<string>                             $unboundUserIds    admins about to lose their binding
     * @param list<string>                             $rebindProviderIds providers whose bindings move to the new
     *                                                                    issuer with this write (count whatever their issuer)
     */
    public function adminAccessPossible(array $providerChanges = [], array $removedUserIds = [], array $unboundUserIds = [], array $rebindProviderIds = []): bool
    {
        $excludedUserIds = $this->bytes(array_values(array_unique([...$removedUserIds, ...$unboundUserIds])));

        foreach ($this->servingProviders(LoginType::Admin->value, $providerChanges) as $id => $provider) {
            [$issuerFilter, $issuerHash] = $this->issuerCondition($id, $provider, $rebindProviderIds);

            $found = $this->connection->fetchOne(
                'SELECT 1
                 FROM `sw6oidc_user_provider` binding
                 INNER JOIN `user` u ON u.`id` = binding.`user_id`
                 WHERE binding.`user_type` = \'admin\'
                   AND u.`active` = 1
                   AND binding.`provider_id` = :provider
                   AND u.`id` NOT IN (:excluded)' . $issuerFilter . '
                 LIMIT 1',
                ['provider' => Uuid::fromHexToBytes($id), 'excluded' => $excludedUserIds, 'issuerHash' => $issuerHash],
                ['provider' => ParameterType::BINARY, 'excluded' => ArrayParameterType::BINARY],
            );

            if ($found !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the invariant holds after the pending changes: password login
     * stays on, or someone can still log in through SSO.
     *
     * @param array<string, array<string, mixed>|null> $providerChanges
     * @param list<string>                             $removedUserIds
     * @param list<string>                             $unboundUserIds
     */
    public function holds(array $providerChanges = [], array $removedUserIds = [], array $unboundUserIds = []): bool
    {
        return !$this->passwordLoginDisabled(LoginType::Admin->value, $providerChanges)
            || $this->adminAccessPossible($providerChanges, $removedUserIds, $unboundUserIds);
    }

    /**
     * Active admins with no binding to a provider that serves admin logins
     * after the pending changes: the accounts SSO-only mode locks out.
     *
     * A binding on a provider's previous issuer doesn't count, exactly as in
     * adminAccessPossible() — so the lockout confirmation and the password-
     * session revocation see the same accounts as the invariant (R6-L1).
     *
     * @param array<string, array<string, mixed>|null> $providerChanges
     * @param list<string>                             $rebindProviderIds see adminAccessPossible()
     *
     * @return list<string> hex user ids
     */
    public function unboundActiveAdminIds(array $providerChanges = [], array $rebindProviderIds = []): array
    {
        $boundIds = [];

        foreach ($this->servingProviders(LoginType::Admin->value, $providerChanges) as $id => $provider) {
            [$issuerFilter, $issuerHash] = $this->issuerCondition($id, $provider, $rebindProviderIds);

            $boundIds[] = $this->connection->fetchFirstColumn(
                'SELECT LOWER(HEX(binding.`user_id`))
                 FROM `sw6oidc_user_provider` binding
                 WHERE binding.`user_type` = \'admin\'
                   AND binding.`provider_id` = :provider' . $issuerFilter,
                ['provider' => Uuid::fromHexToBytes($id), 'issuerHash' => $issuerHash],
                ['provider' => ParameterType::BINARY],
            );
        }

        /** @var list<string> $activeIds */
        $activeIds = $this->connection->fetchFirstColumn('SELECT LOWER(HEX(`id`)) FROM `user` WHERE `active` = 1');

        return array_values(array_diff($activeIds, array_merge([], ...$boundIds)));
    }

    /**
     * The SQL condition (and its parameter) a binding must meet to count for
     * this provider: its current issuer. Legacy providers without an issuer,
     * and a re-bind in progress, accept any binding.
     *
     * @param array<string, mixed> $provider
     * @param list<string>         $rebindProviderIds
     *
     * @return array{string, string}
     */
    private function issuerCondition(string $providerId, array $provider, array $rebindProviderIds): array
    {
        $issuer = trim((string) ($provider['issuer'] ?? ''));

        if ($issuer === '' || \in_array($providerId, $rebindProviderIds, true)) {
            return ['', ''];
        }

        return [' AND binding.`issuer_hash` = :issuerHash', hash('sha256', $issuer)];
    }

    /**
     * Active providers serving this login type after the pending changes.
     *
     * @param array<string, array<string, mixed>|null> $providerChanges
     *
     * @return array<string, array<string, mixed>> hex id => columns
     */
    private function servingProviders(string $loginType, array $providerChanges): array
    {
        $rows = $this->connection->fetchAllAssociative(
            'SELECT LOWER(HEX(`id`)) AS `id`, `is_active`, `login_type`, `disable_non_oidc_admin_login`, `disable_non_oidc_customer_login`, `show_admin_link`,
                    `show_customer_link`, `issuer`
             FROM `sw6oidc_provider`',
        );

        $providers = [];

        foreach ($rows as $row) {
            $providers[(string) $row['id']] = $row;
        }

        foreach ($providerChanges as $id => $columns) {
            $id = strtolower($id);

            if ($columns === null) {
                unset($providers[$id]);

                continue;
            }

            $providers[$id] = [...($providers[$id] ?? ['id' => $id]), ...$columns];
        }

        return array_filter(
            $providers,
            static fn (array $provider): bool => (bool) ($provider['is_active'] ?? false)
                && \in_array($provider['login_type'] ?? null, [$loginType, 'both'], true),
        );
    }

    /**
     * @param list<string> $hexIds
     *
     * @return list<string>
     */
    private function bytes(array $hexIds): array
    {
        // An empty IN () is invalid SQL; a random id never matches.
        $hexIds = $hexIds === [] ? [Uuid::randomHex()] : $hexIds;

        return array_map(Uuid::fromHexToBytes(...), $hexIds);
    }
}
