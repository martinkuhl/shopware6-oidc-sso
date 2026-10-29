<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Config;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleEntity;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingEntity;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingEntity;
use MartinKuhl\Sw6Oidc\Service\Config\OidcConfigTransfer;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupDefinition;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleDefinition;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\IdSearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Write\EntityWriteGatewayInterface;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\Stub\DataAbstractionLayer\StaticDefinitionInstanceRegistry;
use Symfony\Component\Validator\Validation;

#[CoversClass(OidcConfigTransfer::class)]
final class OidcConfigTransferTest extends TestCase
{
    private Sw6OidcEncryptor $encryptor;

    private Sw6OidcProviderDefinition $definition;

    private string $providerId;

    /** @var list<string> provider ids that "exist" */
    private array $existingProviderIds = [];

    /** @var array<string, list<string>> entity => existing ids */
    private array $existingRefs = ['acl_role' => [], 'customer_group' => []];

    /** @var array<string, array<string, string>> entity => name => id */
    private array $refsByName = ['acl_role' => [], 'customer_group' => []];

    /** @var list<array<string, mixed>> */
    private array $upserts = [];

    /** @var list<string> */
    private array $childDeletes = [];

    /** @var list<string> */
    private array $transactionLog = [];

    private string $storedSecret = 'plain-legacy';

    /** What entity hydration produced (an envelope when it could not decrypt). */
    private string $hydratedSecret = 'decrypted-secret';

    protected function setUp(): void
    {
        $this->encryptor = new Sw6OidcEncryptor('app-secret');
        $this->providerId = Uuid::randomHex();

        $registry = new StaticDefinitionInstanceRegistry(
            [Sw6OidcProviderDefinition::class, Sw6OidcAttributeMappingDefinition::class, Sw6OidcRoleMappingDefinition::class, Sw6OidcAccessControlRuleDefinition::class, AclRoleDefinition::class, CustomerGroupDefinition::class],
            Validation::createValidator(),
            $this->createStub(EntityWriteGatewayInterface::class),
        );
        $definition = $registry->getByEntityName(Sw6OidcProviderDefinition::ENTITY_NAME);
        \assert($definition instanceof Sw6OidcProviderDefinition);
        $this->definition = $definition;
    }

    public function testExportOmitsSecretAndInstanceStateByDefault(): void
    {
        $provider = $this->exportOne(OidcConfigTransfer::SECRET_OMIT);

        self::assertArrayNotHasKey('clientSecret', $provider);
        self::assertArrayNotHasKey('lastTestStatus', $provider);
        self::assertArrayNotHasKey('lastTestClaims', $provider);
        self::assertArrayNotHasKey('createdAt', $provider);
        self::assertSame('authelia', $provider['appName']);
        self::assertSame('https://idp.example/token', $provider['accessTokenEndpoint']);
        self::assertSame(['id' => $this->aclRole()->getId(), 'name' => 'Editors'], $provider['defaultAclRole']);
        self::assertSame([['attributeType' => 'firstname', 'attributeName' => 'name', 'transformFunction' => 'split', 'transformParams' => ['separator' => ' ', 'index' => 0]]], $provider['attributeMappings']);
        self::assertSame('admins', $provider['roleMappings'][0]['oidcGroup']);
        self::assertSame(['id' => $this->aclRole()->getId(), 'name' => 'Editors'], $provider['roleMappings'][0]['aclRole']);
        self::assertSame([['claimKey' => 'groups', 'operator' => 'contains', 'value' => 'staff', 'errorMessage' => 'Staff only.', 'sortOrder' => 0]], $provider['accessControlRules']);
    }

    public function testExportPlaintextUsesTheDecryptedEntityValue(): void
    {
        self::assertSame('decrypted-secret', $this->exportOne(OidcConfigTransfer::SECRET_PLAINTEXT)['clientSecret']);
    }

    public function testExportPlaintextRefusesAnUndecryptableSecret(): void
    {
        $this->hydratedSecret = (new Sw6OidcEncryptor('rotated'))->encrypt('secret', 'sw6oidc_provider.client_secret');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('cannot be decrypted');

        $this->exportOne(OidcConfigTransfer::SECRET_PLAINTEXT);
    }

    public function testExportEncryptedKeepsEnvelopeAndEncryptsLegacyPlaintextRows(): void
    {
        $this->storedSecret = 'legacy-plain';
        self::assertSame('legacy-plain', $this->encryptor->decrypt($this->exportOne(OidcConfigTransfer::SECRET_ENCRYPTED)['clientSecret'], 'sw6oidc_provider.client_secret'));

        $this->storedSecret = $this->encryptor->encrypt('already', 'sw6oidc_provider.client_secret');
        self::assertSame($this->storedSecret, $this->exportOne(OidcConfigTransfer::SECRET_ENCRYPTED)['clientSecret']);
    }

    public function testRejectsUnknownFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->transfer()->import(['version' => 99], false, false, false, Context::createDefaultContext());
    }

    public function testNewProviderIsCreatedWithFreshMappingIdsAndResolvedReferences(): void
    {
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $result = $this->transfer()->import($this->exportFile(withSecret: true), false, false, false, Context::createDefaultContext());

        self::assertSame(['authelia'], $result->created);
        self::assertCount(1, $this->upserts);
        $payload = $this->upserts[0];
        self::assertSame($this->providerId, $payload['id']);
        self::assertSame('s3cret', $payload['clientSecret']);
        self::assertSame($this->aclRole()->getId(), $payload['defaultAclRoleId']);
        self::assertTrue(Uuid::isValid($payload['attributeMappings'][0]['id']));
        self::assertSame($this->aclRole()->getId(), $payload['roleMappings'][0]['aclRoleId']);
        self::assertTrue(Uuid::isValid($payload['accessControlRules'][0]['id']));
        self::assertSame(['groups', 'contains', 'staff', 'Staff only.'], [
            $payload['accessControlRules'][0]['claimKey'],
            $payload['accessControlRules'][0]['operator'],
            $payload['accessControlRules'][0]['value'],
            $payload['accessControlRules'][0]['errorMessage'],
        ]);
        self::assertArrayNotHasKey('lastTestStatus', $payload);
    }

    public function testReferenceFallsBackToUniqueName(): void
    {
        $localId = Uuid::randomHex();
        $this->refsByName['acl_role']['Editors'] = $localId;

        $this->transfer()->import($this->exportFile(withSecret: true), false, false, false, Context::createDefaultContext());

        self::assertSame($localId, $this->upserts[0]['defaultAclRoleId']);
        self::assertSame($localId, $this->upserts[0]['roleMappings'][0]['aclRoleId']);
    }

    public function testUnresolvedReferenceFailsTheProviderUnlessSkipped(): void
    {
        $result = $this->transfer()->import($this->exportFile(withSecret: true), false, false, false, Context::createDefaultContext());
        self::assertArrayHasKey('authelia', $result->failed);
        self::assertCount(0, $this->upserts);

        $result = $this->transfer()->import($this->exportFile(withSecret: true), false, true, false, Context::createDefaultContext());
        self::assertSame(['authelia'], $result->created);
        self::assertNull($this->upserts[0]['defaultAclRoleId']);
        self::assertSame([], $this->upserts[0]['roleMappings'], 'an admin_role row without its role is dropped');
        self::assertNotEmpty($result->warnings['authelia']);
    }

    public function testNewConfidentialProviderWithoutSecretFails(): void
    {
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $result = $this->transfer()->import($this->exportFile(withSecret: false), false, false, false, Context::createDefaultContext());

        self::assertStringContainsString('clientSecret', $result->failed['authelia']);
    }

    public function testExistingProviderIsSkippedWithoutOverwrite(): void
    {
        $this->existingProviderIds = [$this->providerId];

        $result = $this->transfer()->import($this->exportFile(withSecret: false), false, false, false, Context::createDefaultContext());

        self::assertSame(['authelia'], $result->skipped);
        self::assertSame([], $this->upserts);
    }

    public function testOverwriteReplacesChildrenAndKeepsStoredSecretWhenAbsent(): void
    {
        $this->existingProviderIds = [$this->providerId];
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $result = $this->transfer()->import($this->exportFile(withSecret: false), true, false, false, Context::createDefaultContext());

        self::assertSame(['authelia'], $result->updated);
        self::assertArrayNotHasKey('clientSecret', $this->upserts[0]);
        self::assertSame(['attribute', 'role', 'rule'], $this->childDeletes);
        self::assertSame(['begin', 'commit'], $this->transactionLog);
    }

    public function testOverwriteKeepsCollectionsAndReferencesMissingFromTheFile(): void
    {
        $this->existingProviderIds = [$this->providerId];
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $file = $this->exportFile(withSecret: false);
        unset($file['providers'][0]['accessControlRules'], $file['providers'][0]['defaultAclRole']);

        $result = $this->transfer()->import($file, true, false, false, Context::createDefaultContext());

        self::assertSame(['attribute', 'role'], $this->childDeletes, 'stored access-control rules are kept (N-L11)');
        self::assertArrayNotHasKey('accessControlRules', $this->upserts[0]);
        self::assertArrayNotHasKey('defaultAclRoleId', $this->upserts[0]);
        self::assertArrayHasKey('attributeMappings', $this->upserts[0]);
        self::assertStringContainsString('accessControlRules', implode(' ', $result->warnings['authelia'] ?? []));
    }

    public function testOverwriteWithAnEmptyListStillClearsThatCollection(): void
    {
        $this->existingProviderIds = [$this->providerId];
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $file = $this->exportFile(withSecret: false);
        $file['providers'][0]['accessControlRules'] = [];

        $this->transfer()->import($file, true, false, false, Context::createDefaultContext());

        self::assertSame(['attribute', 'role', 'rule'], $this->childDeletes);
        self::assertSame([], $this->upserts[0]['accessControlRules']);
    }

    public function testDryRunWrapsEverythingInARolledBackTransaction(): void
    {
        $this->existingRefs['acl_role'] = [$this->aclRole()->getId()];

        $this->transfer()->import($this->exportFile(withSecret: true), false, false, true, Context::createDefaultContext());

        self::assertSame(['begin', 'begin', 'commit', 'rollback'], $this->transactionLog);
    }

    /**
     * @return array<string, mixed>
     */
    private function exportOne(string $secretMode): array
    {
        return $this->transfer()->export(null, $secretMode, Context::createDefaultContext())['providers'][0];
    }

    /**
     * @return array<string, mixed>
     */
    private function exportFile(bool $withSecret): array
    {
        $export = $this->transfer()->export(null, OidcConfigTransfer::SECRET_OMIT, Context::createDefaultContext());

        if ($withSecret) {
            $export['providers'][0]['clientSecret'] = 's3cret';
        }

        return $export;
    }

    private function transfer(): OidcConfigTransfer
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('fetchOne')->willReturnCallback(fn (): string => $this->storedSecret);
        $connection->method('beginTransaction')->willReturnCallback(function (): void {
            $this->transactionLog[] = 'begin';
        });
        $connection->method('rollBack')->willReturnCallback(function (): void {
            $this->transactionLog[] = 'rollback';
        });
        $connection->method('transactional')->willReturnCallback(function (\Closure $work): mixed {
            $this->transactionLog[] = 'begin';
            $result = $work();
            $this->transactionLog[] = 'commit';

            return $result;
        });

        return new OidcConfigTransfer(
            $this->providerRepository(),
            $this->childRepository('attribute'),
            $this->childRepository('role'),
            $this->childRepository('rule'),
            $this->referenceRepository('acl_role'),
            $this->referenceRepository('customer_group'),
            $this->definition,
            $connection,
            $this->encryptor,
        );
    }

    private function providerRepository(): EntityRepository
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturnCallback(fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
            Sw6OidcProviderDefinition::ENTITY_NAME,
            1,
            new Sw6OidcProviderCollection([$this->provider()]),
            null,
            $criteria,
            $context,
        ));
        $repository->method('searchIds')->willReturnCallback(fn (Criteria $criteria): IdSearchResult => $this->ids(
            array_values(array_intersect($criteria->getIds(), $this->existingProviderIds)),
            $criteria,
        ));
        $repository->method('upsert')->willReturnCallback(function (array $payload, Context $context) {
            $this->upserts = [...$this->upserts, ...$payload];

            return \Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent::createWithWrittenEvents([], $context, []);
        });

        return $repository;
    }

    private function childRepository(string $label): EntityRepository
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('searchIds')->willReturnCallback(fn (Criteria $criteria): IdSearchResult => $this->ids([Uuid::randomHex()], $criteria));
        $repository->method('delete')->willReturnCallback(function (array $ids, Context $context) use ($label) {
            $this->childDeletes[] = $label;

            return \Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent::createWithDeletedEvents([], $context, []);
        });

        return $repository;
    }

    private function referenceRepository(string $entity): EntityRepository
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('searchIds')->willReturnCallback(function (Criteria $criteria) use ($entity): IdSearchResult {
            if ($criteria->getIds() !== []) {
                return $this->ids(array_values(array_intersect($criteria->getIds(), $this->existingRefs[$entity])), $criteria);
            }

            $filter = $criteria->getFilters()[0];
            self::assertInstanceOf(EqualsFilter::class, $filter);
            $name = $filter->getValue();

            return $this->ids(isset($this->refsByName[$entity][$name]) ? [$this->refsByName[$entity][$name]] : [], $criteria);
        });

        return $repository;
    }

    /**
     * @param list<mixed> $ids
     */
    private function ids(array $ids, Criteria $criteria): IdSearchResult
    {
        $data = [];

        foreach ($ids as $id) {
            $data[(string) $id] = ['primaryKey' => (string) $id, 'data' => []];
        }

        return new IdSearchResult(\count($ids), $data, $criteria, Context::createDefaultContext());
    }

    private function aclRole(): AclRoleEntity
    {
        static $role = null;

        if ($role === null) {
            $role = new AclRoleEntity();
            $role->setId(Uuid::randomHex());
            $role->setName('Editors');
        }

        return $role;
    }

    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign([
            'id' => $this->providerId,
            'appName' => 'authelia',
            'clientId' => 'shop',
            'clientSecret' => $this->hydratedSecret,
            'accessTokenEndpoint' => 'https://idp.example/token',
            'publicClient' => false,
            'lastTestStatus' => 'passed',
            'lastTestClaims' => ['email' => 'x@example.com'],
            'defaultAclRole' => $this->aclRole(),
        ]);

        $mapping = new Sw6OidcAttributeMappingEntity();
        $mapping->assign(['id' => Uuid::randomHex(), 'attributeType' => 'firstname', 'attributeName' => 'name', 'transformFunction' => 'split', 'transformParams' => ['separator' => ' ', 'index' => 0]]);
        $provider->setAttributeMappings(new Sw6OidcAttributeMappingCollection([$mapping]));

        $role = new Sw6OidcRoleMappingEntity();
        $role->assign(['id' => Uuid::randomHex(), 'mappingType' => 'admin_role', 'oidcGroup' => 'admins', 'sortOrder' => 1, 'aclRole' => $this->aclRole()]);
        $provider->setRoleMappings(new Sw6OidcRoleMappingCollection([$role]));

        $rule = new Sw6OidcAccessControlRuleEntity();
        $rule->assign(['id' => Uuid::randomHex(), 'claimKey' => 'groups', 'operator' => 'contains', 'value' => 'staff', 'errorMessage' => 'Staff only.', 'sortOrder' => 0]);
        $provider->setAccessControlRules(new Sw6OidcAccessControlRuleCollection([$rule]));

        return $provider;
    }
}
