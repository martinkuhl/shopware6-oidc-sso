<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Resolves OIDC group claims via sw6oidc_role_mapping, case-insensitive:
 *
 * - ACL roles (admin): *every* matching role (R3-M11);
 * - customer group: the first match by sort_order (a customer has one).
 *
 * The provider's defaults (`default_acl_role_id`, `default_customer_group_id`)
 * only apply when an account is created; role and group sync on later
 * logins never falls back to them (R3-M11).
 */
class GroupMappingResolver implements ResetInterface
{
    /** @var array<string, list<Sw6OidcRoleMappingEntity>> */
    private array $mappingsByProvider = [];

    /**
     * @param EntityRepository<Sw6OidcRoleMappingCollection> $roleMappingRepository
     */
    public function __construct(private readonly EntityRepository $roleMappingRepository)
    {
    }

    /**
     * Every ACL role a mapping row grants for these groups (no default).
     *
     * @param string[] $oidcGroups
     *
     * @return list<string>
     */
    public function resolveAclRoleIds(Sw6OidcProviderEntity $provider, array $oidcGroups, Context $context): array
    {
        $roleIds = [];

        foreach ($this->matching($provider->getId(), Sw6OidcRoleMappingDefinition::MAPPING_TYPE_ADMIN_ROLE, $oidcGroups, $context) as $mapping) {
            $roleId = $mapping->getAclRoleId();

            if ($roleId !== null) {
                $roleIds[$roleId] = $roleId;
            }
        }

        return array_values($roleIds);
    }

    /**
     * @param string[] $oidcGroups
     * @param bool     $withDefault fall back to the provider's default group (account creation only)
     */
    public function resolveCustomerGroupId(Sw6OidcProviderEntity $provider, array $oidcGroups, Context $context, bool $withDefault = true): ?string
    {
        $mapping = $this->matching($provider->getId(), Sw6OidcRoleMappingDefinition::MAPPING_TYPE_CUSTOMER_GROUP, $oidcGroups, $context)[0] ?? null;

        return $mapping?->getCustomerGroupId() ?? ($withDefault ? $provider->getDefaultCustomerGroupId() : null);
    }

    /**
     * Whether any 'superadmin' mapping row for this provider matches the
     * user's OIDC groups. Deliberately no default/fallback here (unlike
     * resolveAclRoleId/resolveCustomerGroupId) — a superadmin grant must
     * always come from an explicit group match, never an implicit default.
     *
     * @param string[] $oidcGroups
     */
    public function matchesSuperadminGroup(Sw6OidcProviderEntity $provider, array $oidcGroups, Context $context): bool
    {
        if ($oidcGroups === []) {
            return false;
        }

        $normalizedGroups = array_map(mb_strtolower(...), $oidcGroups);

        foreach ($this->mappings($provider->getId(), Sw6OidcRoleMappingDefinition::MAPPING_TYPE_SUPERADMIN, $context) as $mapping) {
            if (\in_array(mb_strtolower($mapping->getOidcGroup()), $normalizedGroups, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The mapping rows of this type matching the groups, in sort order.
     *
     * @param string[] $oidcGroups
     *
     * @return list<Sw6OidcRoleMappingEntity>
     */
    private function matching(string $providerId, string $mappingType, array $oidcGroups, Context $context): array
    {
        if ($oidcGroups === []) {
            return [];
        }

        $normalizedGroups = array_map(mb_strtolower(...), $oidcGroups);

        return array_values(array_filter(
            $this->mappings($providerId, $mappingType, $context),
            static fn (Sw6OidcRoleMappingEntity $mapping): bool => \in_array(mb_strtolower($mapping->getOidcGroup()), $normalizedGroups, true),
        ));
    }

    public function reset(): void
    {
        $this->mappingsByProvider = [];
    }

    /**
     * All of a provider's mapping rows in sort order, loaded once per
     * request: role resolution and the superadmin check used to query
     * separately on every login (L8).
     *
     * @return list<Sw6OidcRoleMappingEntity>
     */
    private function mappings(string $providerId, string $mappingType, Context $context): array
    {
        if (!isset($this->mappingsByProvider[$providerId])) {
            $criteria = new Criteria();
            $criteria->addFilter(new EqualsFilter('providerId', $providerId));
            $criteria->addSorting(new FieldSorting('sortOrder', FieldSorting::ASCENDING));

            $this->mappingsByProvider[$providerId] = array_values(array_filter(
                $this->roleMappingRepository->search($criteria, $context)->getEntities()->getElements(),
                static fn (mixed $mapping): bool => $mapping instanceof Sw6OidcRoleMappingEntity,
            ));
        }

        return array_values(array_filter(
            $this->mappingsByProvider[$providerId],
            static fn (Sw6OidcRoleMappingEntity $mapping): bool => $mapping->getMappingType() === $mappingType,
        ));
    }
}
