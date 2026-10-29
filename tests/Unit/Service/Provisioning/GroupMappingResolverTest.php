<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition as RoleMapping;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\GroupMappingResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Shopware\Core\Framework\Uuid\Uuid;

#[CoversClass(GroupMappingResolver::class)]
final class GroupMappingResolverTest extends TestCase
{
    private ?Criteria $capturedCriteria = null;

    private int $searches = 0;

    public function testResolvesCustomerGroupCaseInsensitively(): void
    {
        $provider = $this->provider();
        $groupId = Uuid::randomHex();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_CUSTOMER_GROUP, 'VIP-Customers', customerGroupId: $groupId),
        ]));

        self::assertSame(
            $groupId,
            $resolver->resolveCustomerGroupId($provider, ['other', 'vip-customers'], Context::createDefaultContext()),
        );
    }

    public function testResolvesAclRoleCaseInsensitivelyAndReturnsAclRoleId(): void
    {
        $provider = $this->provider();
        $aclRoleId = Uuid::randomHex();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'shop-admins', aclRoleId: $aclRoleId, customerGroupId: Uuid::randomHex()),
        ]));

        self::assertSame(
            [$aclRoleId],
            $resolver->resolveAclRoleIds($provider, ['SHOP-ADMINS'], Context::createDefaultContext()),
        );
    }

    /**
     * R3-M11: a user in several mapped groups gets every mapped role.
     */
    public function testEveryMatchingAclRoleIsReturned(): void
    {
        $provider = $this->provider();
        $editor = Uuid::randomHex();
        $support = Uuid::randomHex();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'editors', aclRoleId: $editor, sortOrder: 0),
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'support', aclRoleId: $support, sortOrder: 1),
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'also-editors', aclRoleId: $editor, sortOrder: 2),
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'finance', aclRoleId: Uuid::randomHex(), sortOrder: 3),
        ]));

        self::assertSame([$editor, $support], $resolver->resolveAclRoleIds($provider, ['editors', 'support', 'also-editors'], Context::createDefaultContext()));
    }

    public function testFirstMatchInSortOrderWins(): void
    {
        $provider = $this->provider();
        $firstGroupId = Uuid::randomHex();
        $secondGroupId = Uuid::randomHex();

        // The repository returns rows in the order requested by the criteria
        // (sortOrder ASC); the resolver must take the first matching row.
        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_CUSTOMER_GROUP, 'unrelated', customerGroupId: Uuid::randomHex(), sortOrder: 0),
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_CUSTOMER_GROUP, 'wholesale', customerGroupId: $firstGroupId, sortOrder: 1),
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_CUSTOMER_GROUP, 'retail', customerGroupId: $secondGroupId, sortOrder: 2),
        ]));

        self::assertSame(
            $firstGroupId,
            $resolver->resolveCustomerGroupId($provider, ['retail', 'wholesale'], Context::createDefaultContext()),
        );
    }

    public function testQueriesTheProvidersMappingsOnceSortedBySortOrderAscending(): void
    {
        $provider = $this->provider();

        $resolver = new GroupMappingResolver($this->repositoryReturning([]));
        $resolver->resolveCustomerGroupId($provider, ['any'], Context::createDefaultContext());
        $resolver->resolveAclRoleIds($provider, ['any'], Context::createDefaultContext());
        $resolver->matchesSuperadminGroup($provider, ['any'], Context::createDefaultContext());

        self::assertSame(1, $this->searches, 'one query per provider and request (L8)');

        $criteria = $this->capturedCriteria;
        self::assertNotNull($criteria);
        self::assertSame(['providerId' => $provider->getId()], $this->equalsFilters($criteria));

        $sortings = $criteria->getSorting();
        self::assertCount(1, $sortings);
        self::assertSame('sortOrder', $sortings[0]->getField());
        self::assertSame(FieldSorting::ASCENDING, $sortings[0]->getDirection());
    }

    public function testFallsBackToProviderDefaultCustomerGroupWhenNothingMatches(): void
    {
        $defaultGroupId = Uuid::randomHex();
        $provider = $this->provider();
        $provider->setDefaultCustomerGroupId($defaultGroupId);

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_CUSTOMER_GROUP, 'vip', customerGroupId: Uuid::randomHex()),
        ]));

        self::assertSame(
            $defaultGroupId,
            $resolver->resolveCustomerGroupId($provider, ['not-vip'], Context::createDefaultContext()),
        );
    }

    /**
     * R3-M11: the defaults are for new accounts; sync never falls back to them.
     */
    public function testDefaultsOnlyApplyWhenAsked(): void
    {
        $provider = $this->provider();
        $provider->setDefaultAclRoleId(Uuid::randomHex());
        $provider->setDefaultCustomerGroupId(Uuid::randomHex());

        $resolver = new GroupMappingResolver($this->repositoryReturning([]));

        self::assertSame([], $resolver->resolveAclRoleIds($provider, ['editors'], Context::createDefaultContext()));
        self::assertNull($resolver->resolveCustomerGroupId($provider, ['vip'], Context::createDefaultContext(), withDefault: false));
        self::assertSame($provider->getDefaultCustomerGroupId(), $resolver->resolveCustomerGroupId($provider, ['vip'], Context::createDefaultContext()));
    }

    public function testFallsBackToProviderDefaultWithoutQueryingWhenUserHasNoGroups(): void
    {
        $defaultGroupId = Uuid::randomHex();
        $provider = $this->provider();
        $provider->setDefaultCustomerGroupId($defaultGroupId);

        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('search');

        $resolver = new GroupMappingResolver($repository);

        self::assertSame($defaultGroupId, $resolver->resolveCustomerGroupId($provider, [], Context::createDefaultContext()));
    }

    public function testReturnsNullWhenNothingMatchesAndNoDefaultIsConfigured(): void
    {
        $provider = $this->provider();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'admins', aclRoleId: Uuid::randomHex()),
        ]));

        self::assertSame([], $resolver->resolveAclRoleIds($provider, ['guests'], Context::createDefaultContext()));
        self::assertNull($resolver->resolveCustomerGroupId($provider, ['guests'], Context::createDefaultContext()));
    }

    public function testMatchesSuperadminGroupCaseInsensitively(): void
    {
        $provider = $this->provider();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_SUPERADMIN, 'Root-Admins'),
        ]));

        self::assertTrue($resolver->matchesSuperadminGroup($provider, ['staff', 'ROOT-admins'], Context::createDefaultContext()));
    }

    public function testMatchesSuperadminGroupOnlyConsidersSuperadminRows(): void
    {
        $provider = $this->provider();

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_ADMIN_ROLE, 'root-admins', aclRoleId: Uuid::randomHex()),
        ]));

        self::assertFalse($resolver->matchesSuperadminGroup($provider, ['root-admins'], Context::createDefaultContext()));
    }

    public function testResetForgetsTheMemo(): void
    {
        $provider = $this->provider();
        $resolver = new GroupMappingResolver($this->repositoryReturning([]));

        $resolver->resolveAclRoleIds($provider, ['any'], Context::createDefaultContext());
        $resolver->reset();
        $resolver->resolveAclRoleIds($provider, ['any'], Context::createDefaultContext());

        self::assertSame(2, $this->searches);
    }

    public function testMatchesSuperadminGroupReturnsFalseWithoutMatchEvenWhenDefaultRoleIsConfigured(): void
    {
        $provider = $this->provider();
        $provider->setDefaultAclRoleId(Uuid::randomHex());
        $provider->setDefaultCustomerGroupId(Uuid::randomHex());

        $resolver = new GroupMappingResolver($this->repositoryReturning([
            $this->mapping($provider->getId(), RoleMapping::MAPPING_TYPE_SUPERADMIN, 'root-admins'),
        ]));

        self::assertFalse($resolver->matchesSuperadminGroup($provider, ['editors'], Context::createDefaultContext()));
    }

    public function testMatchesSuperadminGroupReturnsFalseWithoutQueryingWhenUserHasNoGroups(): void
    {
        $provider = $this->provider();
        $provider->setDefaultAclRoleId(Uuid::randomHex());

        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('search');

        $resolver = new GroupMappingResolver($repository);

        self::assertFalse($resolver->matchesSuperadminGroup($provider, [], Context::createDefaultContext()));
    }

    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId(Uuid::randomHex());

        return $provider;
    }

    private function mapping(
        string $providerId,
        string $mappingType,
        string $oidcGroup,
        ?string $aclRoleId = null,
        ?string $customerGroupId = null,
        int $sortOrder = 0,
    ): Sw6OidcRoleMappingEntity {
        $entity = new Sw6OidcRoleMappingEntity();
        $entity->setId(Uuid::randomHex());
        $entity->setProviderId($providerId);
        $entity->setMappingType($mappingType);
        $entity->setOidcGroup($oidcGroup);
        $entity->setAclRoleId($aclRoleId);
        $entity->setCustomerGroupId($customerGroupId);
        $entity->setSortOrder($sortOrder);

        return $entity;
    }

    /**
     * @param Sw6OidcRoleMappingEntity[] $entities
     */
    private function repositoryReturning(array $entities): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('search')->willReturnCallback(
            function (Criteria $criteria, Context $context) use ($entities): EntitySearchResult {
                $this->capturedCriteria = $criteria;
                ++$this->searches;

                return new EntitySearchResult(
                    RoleMapping::ENTITY_NAME,
                    \count($entities),
                    new Sw6OidcRoleMappingCollection($entities),
                    null,
                    $criteria,
                    $context,
                );
            },
        );

        return $repository;
    }

    /**
     * @return array<string, mixed>
     */
    private function equalsFilters(Criteria $criteria): array
    {
        $filters = [];

        foreach ($criteria->getFilters() as $filter) {
            self::assertInstanceOf(EqualsFilter::class, $filter);
            $filters[$filter->getField()] = $filter->getValue();
        }

        return $filters;
    }
}
