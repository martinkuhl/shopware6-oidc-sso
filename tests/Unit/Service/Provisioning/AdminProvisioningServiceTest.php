<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AdminAfterCreateEvent;
use MartinKuhl\Sw6Oidc\Event\AdminBeforeCreateEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AdminProvisioningService;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AdminRoleStore;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AvatarFetcher;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AdminProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\ExternalIdentity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\GroupMappingResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\IdentityResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Provisioning\TimeZoneValidator;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Shopware\Core\Content\Media\File\MediaFile;
use Shopware\Core\Content\Media\MediaService;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleCollection;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\IdSearchResult;
use Shopware\Core\Framework\Event\NestedEventCollection;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\User\UserCollection;
use Shopware\Core\System\User\UserDefinition;
use Shopware\Core\System\User\UserEntity;
use Symfony\Component\EventDispatcher\EventDispatcher;

#[CoversClass(AdminProvisioningService::class)]
final class AdminProvisioningServiceTest extends TestCase
{
    private ?EventDispatcher $eventDispatcher = null;

    private Context $context;

    private ?UserEntity $existingUser = null;

    private ?string $boundProviderId = null;

    private ?string $boundSub = null;

    /** @var list<array{userId: string, aclRoleId: string}> */
    private array $roleDeletes = [];

    private bool $otherActiveSuperadmin = true;

    /** @var list<string> roles role sync granted earlier (sw6oidc_managed_acl_role) */
    private array $managedRoles = [];

    /** @var list<string> */
    private array $rememberedRoles = [];

    private string $subject = 'idp-subject-1';

    private bool $emailVerified = true;

    /** @var string[] */
    private array $takenUsernames = [];

    /** @var array<string, string> locale code => locale id */
    private array $localeIds = [];

    private string $fallbackLocaleId;

    private bool $superadminMatch = false;

    private ?string $resolvedAclRoleId = null;

    /** @var list<array<string, mixed>> */
    private array $userCreates = [];

    /** @var list<array<string, mixed>> */
    private array $userUpdates = [];

    /** @var list<array<string, mixed>> */
    private array $bindingCreates = [];

    /** @var list<array<string, mixed>> */
    private array $mediaUpdates = [];

    private GroupMappingResolver&MockObject $groupMappingResolver;

    private AvatarFetcher&MockObject $avatarFetcher;

    private MediaService&MockObject $mediaService;

    protected function setUp(): void
    {
        $this->context = Context::createDefaultContext();
        $this->fallbackLocaleId = Uuid::randomHex();

        $this->groupMappingResolver = $this->createMock(GroupMappingResolver::class);
        $this->groupMappingResolver->method('matchesSuperadminGroup')
            ->willReturnCallback(fn (): bool => $this->superadminMatch);
        $this->groupMappingResolver->method('resolveAclRoleIds')
            ->willReturnCallback(fn (): array => $this->resolvedAclRoleId !== null ? [$this->resolvedAclRoleId] : []);

        $this->avatarFetcher = $this->createMock(AvatarFetcher::class);
        $this->mediaService = $this->createMock(MediaService::class);
    }

    public function testExistingAdminBoundToDifferentProviderThrowsProviderMismatch(): void
    {
        $this->existingUser = $this->user('jane');
        $this->boundProviderId = Uuid::randomHex();

        $provider = $this->provider();
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setSyncAdminProfileOnSso(true);

        try {
            $this->findOrCreate($provider, new MappedProfile('jane@example.com', firstName: 'Jane'), $this->context);
            self::fail('Expected ProviderMismatchException');
        } catch (ProviderMismatchException) {
        }

        self::assertSame([], $this->bindingCreates);
        self::assertSame([], $this->userUpdates);
        self::assertSame([], $this->userCreates);
    }

    public function testExistingAdminIsNotLinkedByEmailUnlessTheProviderAllowsIt(): void
    {
        $this->existingUser = $this->user('jane');
        $provider = $this->provider();
        $provider->setLinkExistingAccounts(false);

        $this->expectException(AccountLinkingRequiredException::class);

        try {
            $this->findOrCreate($provider, new MappedProfile('jane@example.com'), $this->context);
        } finally {
            self::assertSame([], $this->bindingCreates);
            self::assertSame([], $this->userCreates);
        }
    }

    public function testExistingSuperadminIsNeverLinkedByEmail(): void
    {
        $this->existingUser = $this->user('root');
        $this->existingUser->setAdmin(true);

        $this->expectException(AccountLinkingRequiredException::class);

        $this->findOrCreate($this->provider(), new MappedProfile('root@example.com'), $this->context);
    }

    public function testUnverifiedEmailIsRefusedWhenTheProviderRequiresVerification(): void
    {
        $this->existingUser = $this->user('jane');
        $this->emailVerified = false;

        $this->expectException(EmailNotVerifiedException::class);

        $this->findOrCreate($this->provider(), new MappedProfile('jane@example.com'), $this->context);
    }

    public function testBoundSubjectResolvesTheAccountWhateverTheEmailClaimSays(): void
    {
        $this->existingUser = $this->user('jane');
        $provider = $this->provider();
        $provider->setLinkExistingAccounts(false);
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;

        $result = $this->findOrCreate($provider, new MappedProfile('renamed@example.com'), $this->context);

        self::assertSame($this->existingUser->getId(), $result->getId());
        self::assertSame([], $this->userCreates);
    }

    public function testAnInactiveBoundAdminIsRefusedBeforeAnySync(): void
    {
        $this->existingUser = $this->user('jane');
        $this->existingUser->setActive(false);
        $provider = $this->provider();
        $provider->setSyncAdminProfileOnSso(true);
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;

        try {
            $this->findOrCreate($provider, new MappedProfile('jane@example.com', firstName: 'Changed'), $this->context);
            self::fail('Expected AdminProvisioningDeniedException');
        } catch (AdminProvisioningDeniedException $exception) {
            // R3-L28: no sync (or anything else) for an account that can't log in.
            self::assertSame(AdminProvisioningDeniedException::REASON_ACCOUNT_INACTIVE, $exception->reason);
            self::assertSame([], $this->userUpdates);
        }
    }

    public function testNewAdminIsBoundToTheSubject(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();

        $this->findOrCreate($provider, new MappedProfile('new@example.com'), $this->context);

        self::assertCount(1, $this->bindingCreates);
        self::assertSame($this->subject, $this->bindingCreates[0]['sub']);
        self::assertSame('https://idp.example.com', $this->bindingCreates[0]['issuer']);
    }

    public function testListenerCannotChangeTheVerifiedEmail(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();

        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addListener(AdminBeforeCreateEvent::class, static function (AdminBeforeCreateEvent $event): void {
            $event->setPayload([...$event->getPayload(), 'email' => 'attacker@example.com']);
        });

        $this->findOrCreate($provider, new MappedProfile('new@example.com'), $this->context);

        self::assertSame('new@example.com', $this->userCreates[0]['email']);
    }

    /**
     * Every admin is privileged (R3-L23): even with linking by email on, an
     * existing admin account is only ever connected explicitly.
     */
    public function testExistingAdminIsNeverLinkedByEmail(): void
    {
        $this->existingUser = $this->user('jane');
        $provider = $this->provider();
        $provider->setLinkExistingAccounts(true);

        try {
            $this->findOrCreate($provider, new MappedProfile('jane@example.com', firstName: 'Jane', groups: ['admins']), $this->context);
            self::fail('Expected AccountLinkingRequiredException');
        } catch (AccountLinkingRequiredException) {
        }

        self::assertSame([], $this->bindingCreates);
        self::assertSame([], $this->userUpdates);
    }

    /**
     * R3-M10: whoever holds the email at the IdP today must not inherit an
     * admin account through its legacy (pre-subject) binding.
     */
    public function testLegacyBindingOfAnAdminIsNotUpgradedAutomatically(): void
    {
        $this->existingUser = $this->user('jane');
        $provider = $this->provider();
        $this->boundProviderId = $provider->getId();

        $this->expectException(AccountLinkingRequiredException::class);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com'), $this->context);
    }

    public function testSyncRoleGrantsSuperadminWhenAllowedAndGroupMatches(): void
    {
        $this->existingUser = $this->user('jane');
        $this->superadminMatch = true;
        $this->resolvedAclRoleId = Uuid::randomHex();

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setAllowSuperadminGroupMapping(true);

        $this->groupMappingResolver->expects(self::never())->method('resolveAclRoleIds');

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['root']), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'admin' => true]], $this->userUpdates);
    }

    public function testSyncRoleIgnoresStraySuperadminMappingWhenProviderToggleIsOff(): void
    {
        $this->existingUser = $this->user('jane');
        $this->superadminMatch = true;
        $roleId = Uuid::randomHex();
        $this->resolvedAclRoleId = $roleId;

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setAllowSuperadminGroupMapping(false);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['root']), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'aclRoles' => [['id' => $roleId]]]], $this->userUpdates);
        foreach ($this->userUpdates as $update) {
            self::assertArrayNotHasKey('admin', $update);
        }
    }

    public function testSyncRoleAppliesResolvedAclRoleWhenNoSuperadminMatch(): void
    {
        $this->existingUser = $this->user('jane');
        $roleId = Uuid::randomHex();
        $this->resolvedAclRoleId = $roleId;

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setAllowSuperadminGroupMapping(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['editors']), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'aclRoles' => [['id' => $roleId]]]], $this->userUpdates);
    }

    /**
     * R3-M11: only roles role sync granted itself are taken away; a role
     * granted by hand in Shopware stays.
     */
    public function testSyncRoleRemovesOnlyManagedRolesTheIdpNoLongerGrants(): void
    {
        $this->existingUser = $this->user('jane');
        $keptRole = Uuid::randomHex();
        $revokedRole = Uuid::randomHex();
        $manualRole = Uuid::randomHex();
        $this->existingUser->setAclRoles(new AclRoleCollection([$this->role($keptRole), $this->role($revokedRole), $this->role($manualRole)]));
        $this->managedRoles = [$keptRole, $revokedRole];
        $this->resolvedAclRoleId = $keptRole;

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminRoleOnSso(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['editors']), $this->context);

        self::assertSame([['userId' => $this->existingUser->getId(), 'aclRoleId' => $revokedRole]], $this->roleDeletes);
        self::assertSame([], $this->userUpdates, 'the kept role needs no write');
    }

    public function testSyncRoleAddsEveryMappedRoleAndRemembersIt(): void
    {
        $this->existingUser = $this->user('jane');
        $first = Uuid::randomHex();
        $second = Uuid::randomHex();
        $this->groupMappingResolver = $this->createMock(GroupMappingResolver::class);
        $this->groupMappingResolver->method('resolveAclRoleIds')->willReturn([$first, $second]);

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminRoleOnSso(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['editors', 'support']), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'aclRoles' => [['id' => $first], ['id' => $second]]]], $this->userUpdates);
        self::assertSame([$first, $second], $this->rememberedRoles);
    }

    /**
     * R3-M11: removed from every IdP group, a superadmin loses the flag with
     * the opt-in, even though no role resolves.
     */
    public function testSuperadminIsRevokedWhenNoGroupResolves(): void
    {
        $this->existingUser = $this->user('root');
        $this->existingUser->setAdmin(true);

        $provider = $this->provider();
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setRevokeSuperadminOnSso(true);
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;

        $this->findOrCreate($provider, new MappedProfile('root@example.com', groups: []), $this->context);

        self::assertContains(['id' => $this->existingUser->getId(), 'admin' => false], $this->userUpdates);
    }

    public function testSuperadminIsOnlyRevokedWithTheOptIn(): void
    {
        $this->existingUser = $this->user('root');
        $this->existingUser->setAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();

        $provider = $this->provider();
        $provider->setSyncAdminRoleOnSso(true);
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;

        $this->findOrCreate($provider, new MappedProfile('root@example.com', groups: ['editors']), $this->context);
        self::assertNotContains(['id' => $this->existingUser->getId(), 'admin' => false], $this->userUpdates);

        $provider->setRevokeSuperadminOnSso(true);
        $this->findOrCreate($provider, new MappedProfile('root@example.com', groups: ['editors']), $this->context);
        self::assertContains(['id' => $this->existingUser->getId(), 'admin' => false], $this->userUpdates);
    }

    public function testTheLastSuperadminIsNeverRevoked(): void
    {
        $this->existingUser = $this->user('root');
        $this->existingUser->setAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $this->otherActiveSuperadmin = false;

        $provider = $this->provider();
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setRevokeSuperadminOnSso(true);
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;

        $this->findOrCreate($provider, new MappedProfile('root@example.com', groups: ['editors']), $this->context);

        self::assertNotContains(['id' => $this->existingUser->getId(), 'admin' => false], $this->userUpdates);
    }

    private function role(string $id): AclRoleEntity
    {
        $role = new AclRoleEntity();
        $role->setId($id);

        return $role;
    }

    public function testSyncRoleNeverRevokesWhenNothingMatches(): void
    {
        $this->existingUser = $this->user('jane');
        $this->existingUser->setAdmin(true);

        $provider = $this->provider();
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;
        $provider->setSyncAdminRoleOnSso(true);
        $provider->setAllowSuperadminGroupMapping(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: []), $this->context);

        self::assertSame([], $this->userUpdates);
    }

    public function testSyncRoleIsSkippedWhenToggleIsOff(): void
    {
        $this->existingUser = $this->user('jane');
        $this->superadminMatch = true;
        $this->resolvedAclRoleId = Uuid::randomHex();

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setAllowSuperadminGroupMapping(true);

        $this->groupMappingResolver->expects(self::never())->method('matchesSuperadminGroup');
        $this->groupMappingResolver->expects(self::never())->method('resolveAclRoleIds');

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', groups: ['root']), $this->context);

        self::assertSame([], $this->userUpdates);
    }

    public function testSyncProfileOnlyUpdatesMappedNonNullFields(): void
    {
        $this->existingUser = $this->user('jane');

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', firstName: 'Janet'), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'firstName' => 'Janet']], $this->userUpdates);
    }

    public function testSyncProfileAppliesAllMappedFieldsIncludingLocaleAndTimeZone(): void
    {
        $this->existingUser = $this->user('jane');
        $deLocaleId = Uuid::randomHex();
        $this->localeIds['de-DE'] = $deLocaleId;

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->findOrCreate($provider, new MappedProfile(
            'jane@example.com',
            firstName: 'Janet',
            lastName: 'Doe',
            locale: 'de-DE',
            zoneinfo: 'Europe/Berlin',
        ), $this->context);

        self::assertSame([[
            'id' => $this->existingUser->getId(),
            'firstName' => 'Janet',
            'lastName' => 'Doe',
            'localeId' => $deLocaleId,
            'timeZone' => 'Europe/Berlin',
        ]], $this->userUpdates);
    }

    public function testSyncProfileSkipsInvalidTimeZoneAndWritesNothingWhenNothingIsMapped(): void
    {
        $this->existingUser = $this->user('jane');

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', zoneinfo: 'Not/AZone'), $this->context);

        self::assertSame([], $this->userUpdates);
    }

    public function testSyncProfileImportsAvatarReusingExistingMediaId(): void
    {
        $existingAvatarId = Uuid::randomHex();
        $this->existingUser = $this->user('jane');
        $this->existingUser->setAvatarId($existingAvatarId);

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->expectAvatarImport('https://idp.example.com/a.png', $existingAvatarId, $existingAvatarId);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', picture: 'https://idp.example.com/a.png'), $this->context);

        self::assertSame([[
            'id' => $this->existingUser->getId(),
            'avatarId' => $existingAvatarId,
            'customFields' => [AdminProvisioningService::AVATAR_URL_HASH_FIELD => hash('sha256', 'https://idp.example.com/a.png')],
        ]], $this->userUpdates);
        self::assertSame([['id' => $existingAvatarId, 'private' => false]], $this->mediaUpdates);
    }

    public function testSyncProfileSkipsUnchangedAvatar(): void
    {
        $this->existingUser = $this->user('jane');
        $this->existingUser->setAvatarId(Uuid::randomHex());
        $this->existingUser->setCustomFields([AdminProvisioningService::AVATAR_URL_HASH_FIELD => hash('sha256', 'https://idp.example.com/a.png')]);

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->avatarFetcher->expects(self::never())->method('fetch');
        $this->mediaService->expects(self::never())->method('saveMediaFile');

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', picture: 'https://idp.example.com/a.png'), $this->context);

        self::assertSame([], $this->userUpdates);
    }

    public function testSyncProfileSwallowsAvatarFetchFailure(): void
    {
        $this->existingUser = $this->user('jane');

        $provider = $this->provider();

        $this->bindTo($provider);
        $provider->setSyncAdminProfileOnSso(true);

        $this->avatarFetcher->method('fetch')->willThrowException(new \RuntimeException('unreachable'));
        $this->mediaService->expects(self::never())->method('saveMediaFile');

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', firstName: 'Jane', picture: 'https://idp.example.com/a.png'), $this->context);

        self::assertSame([['id' => $this->existingUser->getId(), 'firstName' => 'Jane']], $this->userUpdates);
        self::assertSame([], $this->mediaUpdates);
    }

    public function testNotFoundWithAutoCreateDisabledIsDenied(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(false);
        $this->resolvedAclRoleId = Uuid::randomHex();

        try {
            $this->findOrCreate($provider, new MappedProfile('new@example.com'), $this->context);
            self::fail('Expected AdminProvisioningDeniedException');
        } catch (AdminProvisioningDeniedException $e) {
            self::assertSame(AdminProvisioningDeniedException::REASON_AUTO_CREATE_DISABLED, $e->reason);
            self::assertStringNotContainsString('new@example.com', $e->getMessage(), 'no email in log messages (R3-L24)');
        }

        self::assertSame([], $this->userCreates);
        self::assertSame([], $this->bindingCreates);
    }

    public function testNotFoundWithoutResolvedRoleIsDenied(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $provider->setAllowSuperadminGroupMapping(true);

        try {
            $this->findOrCreate($provider, new MappedProfile('new@example.com', groups: ['nobody']), $this->context);
            self::fail('Expected AdminProvisioningDeniedException');
        } catch (AdminProvisioningDeniedException $e) {
            self::assertSame(AdminProvisioningDeniedException::REASON_NO_ROLE, $e->reason);
        }

        self::assertSame([], $this->userCreates);
        self::assertSame([], $this->bindingCreates);
    }

    public function testStraySuperadminMappingAloneNeverGrantsOnCreate(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $provider->setAllowSuperadminGroupMapping(false);
        $this->superadminMatch = true;

        try {
            $this->findOrCreate($provider, new MappedProfile('new@example.com', groups: ['root']), $this->context);
            self::fail('Expected AdminProvisioningDeniedException');
        } catch (AdminProvisioningDeniedException $e) {
            self::assertSame(AdminProvisioningDeniedException::REASON_NO_ROLE, $e->reason);
        }

        self::assertSame([], $this->userCreates);
    }

    public function testStraySuperadminMappingWithToggleOffCreatesRegularAdminWithAclRole(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $provider->setAllowSuperadminGroupMapping(false);
        $this->superadminMatch = true;
        $roleId = Uuid::randomHex();
        $this->resolvedAclRoleId = $roleId;

        $this->findOrCreate($provider, new MappedProfile('new@example.com', groups: ['root']), $this->context);

        self::assertCount(1, $this->userCreates);
        self::assertFalse($this->userCreates[0]['admin']);
        self::assertSame([['id' => $roleId]], $this->userCreates[0]['aclRoles']);
    }

    public function testCreateDispatchesBeforeAndAfterEventsAndHonorsPayloadChanges(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $dispatched = [];
        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addListener(AdminBeforeCreateEvent::class, static function (AdminBeforeCreateEvent $event) use (&$dispatched): void {
            $dispatched[] = 'before';
            $event->setPayload([...$event->getPayload(), 'title' => 'SSO user', 'id' => 'ignored']);
        });
        $this->eventDispatcher->addListener(AdminAfterCreateEvent::class, static function (AdminAfterCreateEvent $event) use (&$dispatched): void {
            $dispatched[] = 'after:' . $event->getUser()->getId();
        });

        $result = $this->findOrCreate($provider, new MappedProfile('new@example.com'), $this->context);

        self::assertCount(1, $this->userCreates);
        self::assertSame('SSO user', $this->userCreates[0]['title']);
        self::assertSame($result->getId(), $this->userCreates[0]['id'], 'the id cannot be changed by a listener');
        self::assertSame(['before', 'after:' . $result->getId()], $dispatched);
    }

    public function testExistingAdminDispatchesNoCreateEvents(): void
    {
        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addListener(AdminBeforeCreateEvent::class, static fn () => self::fail('unexpected before-create event'));
        $this->eventDispatcher->addListener(AdminAfterCreateEvent::class, static fn () => self::fail('unexpected after-create event'));
        $this->existingUser = $this->user('existing');

        $provider = $this->provider();

        $this->bindTo($provider);

        $this->findOrCreate($provider, new MappedProfile('existing@example.com'), $this->context);

        self::assertSame([], $this->userCreates);
    }

    public function testCreatesSuperadminWhenToggleOnAndGroupMatches(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $provider->setAllowSuperadminGroupMapping(true);
        $this->superadminMatch = true;

        $this->groupMappingResolver->expects(self::never())->method('resolveAclRoleIds');

        $this->findOrCreate($provider, new MappedProfile('root@example.com', groups: ['root']), $this->context);

        self::assertCount(1, $this->userCreates);
        self::assertTrue($this->userCreates[0]['admin']);
        self::assertSame([], $this->userCreates[0]['aclRoles']);
    }

    public function testCreatePayloadBindingAndReturnedEntity(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $roleId = Uuid::randomHex();
        $this->resolvedAclRoleId = $roleId;
        $deLocaleId = Uuid::randomHex();
        $this->localeIds['de-DE'] = $deLocaleId;

        $result = $this->findOrCreate($provider, new MappedProfile(
            'jane.doe@example.com',
            username: 'jdoe',
            firstName: 'Jane',
            lastName: 'Doe',
            locale: 'de-DE',
            zoneinfo: 'Europe/Berlin',
            groups: ['editors'],
        ), $this->context);

        self::assertCount(1, $this->userCreates);
        $payload = $this->userCreates[0];

        self::assertTrue(Uuid::isValid($payload['id']));
        self::assertSame(64, \strlen($payload['password']));
        unset($payload['password']);

        self::assertSame([
            'id' => $payload['id'],
            'localeId' => $deLocaleId,
            'username' => 'jdoe',
            'firstName' => 'Jane',
            'lastName' => 'Doe',
            'email' => 'jane.doe@example.com',
            'active' => true,
            'admin' => false,
            'aclRoles' => [['id' => $roleId]],
            'timeZone' => 'Europe/Berlin',
        ], $payload);

        self::assertSame([], $this->userUpdates);
        self::assertCount(1, $this->bindingCreates);
        self::assertSame($payload['id'], $this->bindingCreates[0]['userId']);
        self::assertSame($provider->getId(), $this->bindingCreates[0]['providerId']);
        self::assertSame(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $this->bindingCreates[0]['userType']);
        self::assertSame($payload['id'], $result->getId());
    }

    public function testCreateFallsBackForMissingNamesLocaleAndInvalidTimeZone(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $enLocaleId = Uuid::randomHex();
        $this->localeIds['en-GB'] = $enLocaleId;

        $this->findOrCreate($provider, new MappedProfile(
            'jane@example.com',
            locale: 'xx-XX',
            zoneinfo: 'Mars/Olympus',
        ), $this->context);

        $payload = $this->userCreates[0];
        self::assertSame('jane', $payload['username']);
        self::assertSame('jane', $payload['firstName'], 'never the email address as a name (L9)');
        self::assertSame('-', $payload['lastName']);
        self::assertSame($enLocaleId, $payload['localeId']);
        self::assertArrayNotHasKey('timeZone', $payload);
    }

    public function testCreateFallsBackToFirstAvailableLocaleWhenEnGbIsMissing(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();

        $this->findOrCreate($provider, new MappedProfile('jane@example.com'), $this->context);

        self::assertSame($this->fallbackLocaleId, $this->userCreates[0]['localeId']);
    }

    public function testCreateDerivesSanitizedUsernameFromEmailLocalPartAndDeduplicates(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $this->takenUsernames = ['jane.doe', 'jane.doe1'];

        $this->findOrCreate($provider, new MappedProfile('jane.doe+test@example.com'), $this->context);

        // "+" is stripped by the sanitizer: "jane.doe+test" -> "jane.doetest"
        self::assertSame('jane.doetest', $this->userCreates[0]['username']);
    }

    public function testCreateDeduplicatesMappedUsernameWithIncrementingSuffix(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $this->takenUsernames = ['jane', 'jane1', 'jane2'];

        $this->findOrCreate($provider, new MappedProfile('someone@example.com', username: 'jane'), $this->context);

        self::assertSame('jane3', $this->userCreates[0]['username']);
    }

    public function testUsernameProbeIsBoundedAndEndsInARandomSuffix(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $this->takenUsernames = ['jane', 'jane1', 'jane2', 'jane3', 'jane4'];

        $this->findOrCreate($provider, new MappedProfile('someone@example.com', username: 'jane'), $this->context);

        // Not "jane5" after an ever longer loop of queries (R3-L25).
        self::assertMatchesRegularExpression('/^jane-[0-9a-f]{4}$/', $this->userCreates[0]['username']);
    }

    public function testCreateUsesFallbackUsernameWhenSanitizedBaseIsEmpty(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $this->takenUsernames = ['user'];

        $this->findOrCreate($provider, new MappedProfile('x@example.com', username: '!!!'), $this->context);

        self::assertSame('user1', $this->userCreates[0]['username']);
    }

    public function testCreateImportsAvatarAndUpdatesUser(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();
        $newAvatarId = Uuid::randomHex();

        $this->expectAvatarImport('https://idp.example.com/a.png', null, $newAvatarId);

        $this->findOrCreate($provider, new MappedProfile('jane@example.com', picture: 'https://idp.example.com/a.png'), $this->context);

        $userId = $this->userCreates[0]['id'];
        self::assertArrayNotHasKey('avatarId', $this->userCreates[0]);
        self::assertSame([[
            'id' => $userId,
            'avatarId' => $newAvatarId,
            'customFields' => [AdminProvisioningService::AVATAR_URL_HASH_FIELD => hash('sha256', 'https://idp.example.com/a.png')],
        ]], $this->userUpdates);
        self::assertSame([['id' => $newAvatarId, 'private' => false]], $this->mediaUpdates);
    }

    public function testCreateDoesNotFailLoginWhenAvatarImportFails(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateAdmin(true);
        $this->resolvedAclRoleId = Uuid::randomHex();

        $this->avatarFetcher->method('fetch')->willThrowException(new \RuntimeException('blocked'));

        $result = $this->findOrCreate($provider, new MappedProfile('jane@example.com', picture: 'https://10.0.0.1/a.png'), $this->context);

        self::assertCount(1, $this->userCreates);
        self::assertSame([], $this->userUpdates);
        self::assertSame($this->userCreates[0]['id'], $result->getId());
    }

    private function findOrCreate(Sw6OidcProviderEntity $provider, MappedProfile $profile, Context $context, ?ExternalIdentity $identity = null): UserEntity
    {
        return $this->createService()->findOrCreateAdmin(
            $provider,
            $profile,
            $identity ?? new ExternalIdentity($provider->getId(), 'https://idp.example.com', $this->subject, $profile->email, $this->emailVerified),
            $context,
        );
    }

    private function createService(): AdminProvisioningService
    {
        $bindingService = new UserProviderBindingService($this->userProviderRepository());

        return new AdminProvisioningService(
            $this->userRepository(),
            $this->localeRepository(),
            $this->mediaRepository(),
            $this->groupMappingResolver,
            $bindingService,
            new IdentityResolver($bindingService, $this->createStub(LoggerInterface::class)),
            $this->mediaService,
            $this->avatarFetcher,
            new TimeZoneValidator(),
            $this->createStub(LoggerInterface::class),
            $this->eventDispatcher ??= new EventDispatcher(),
            $this->aclUserRoleRepository(),
            $this->connection(),
            $this->roleStore(),
        );
    }

    private function bindTo(Sw6OidcProviderEntity $provider): void
    {
        $this->boundProviderId = $provider->getId();
        $this->boundSub = $this->subject;
    }

    private function connection(): Connection
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('transactional')->willReturnCallback(static fn (\Closure $callback): mixed => $callback($connection));

        return $connection;
    }

    private function roleStore(): AdminRoleStore
    {
        $test = $this;

        return new class($this->createStub(Connection::class), $test) extends AdminRoleStore {
            public function __construct(Connection $connection, private readonly AdminProvisioningServiceTest $test)
            {
                parent::__construct($connection);
            }

            public function roleIds(string $userId): array
            {
                return $this->test->currentRoleIds();
            }

            public function managedRoleIds(string $userId): array
            {
                return $this->test->managedRoleIds();
            }

            public function rememberManaged(string $userId, array $roleIds, string $providerId): void
            {
                $this->test->rememberRoles($roleIds);
            }

            public function forgetManaged(string $userId, array $roleIds): void
            {
            }

            public function revokeSuperadminUnlessLast(string $userId, callable $revoke): bool
            {
                if (!$this->test->hasOtherActiveSuperadmin()) {
                    return false;
                }

                $revoke();

                return true;
            }
        };
    }

    /**
     * @return list<string>
     */
    public function currentRoleIds(): array
    {
        return array_values(array_map(static fn (AclRoleEntity $role): string => $role->getId(), $this->existingUser?->getAclRoles()?->getElements() ?? []));
    }

    /**
     * @return list<string>
     */
    public function managedRoleIds(): array
    {
        return $this->managedRoles;
    }

    /**
     * @param list<string> $roleIds
     */
    public function rememberRoles(array $roleIds): void
    {
        array_push($this->rememberedRoles, ...$roleIds);
    }

    public function hasOtherActiveSuperadmin(): bool
    {
        return $this->otherActiveSuperadmin;
    }

    private function aclUserRoleRepository(): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('delete')->willReturnCallback(function (array $ids, Context $context): EntityWrittenContainerEvent {
            array_push($this->roleDeletes, ...$ids);

            return $this->writtenEvent($context);
        });

        return $repository;
    }

    private function expectAvatarImport(string $url, ?string $expectedExistingMediaId, string $returnedMediaId): void
    {
        $this->avatarFetcher->expects(self::once())
            ->method('fetch')
            ->willReturnCallback(static function (string $pictureUrl, string $tempFile) use ($url): MediaFile {
                self::assertSame($url, $pictureUrl);

                return new MediaFile($tempFile, 'image/png', 'png', 123);
            });
        $this->mediaService->expects(self::once())
            ->method('saveMediaFile')
            ->willReturnCallback(static function (
                MediaFile $file,
                string $name,
                Context $ctx,
                ?string $folder,
                ?string $mediaId,
                bool $private,
            ) use (
                $expectedExistingMediaId,
                $returnedMediaId,
            ): string {
                self::assertStringStartsWith('sw6oidc-avatar-', $name);
                self::assertSame('user', $folder);
                self::assertSame($expectedExistingMediaId, $mediaId);
                self::assertFalse($private);

                return $returnedMediaId;
            });
    }

    /**
     * Linking by verified email is opted into here so the pre-subject tests
     * keep exercising find/create/sync; the linking policy itself is covered
     * by IdentityResolverTest and the tests at the top of this class.
     */
    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId(Uuid::randomHex());
        $provider->setLinkExistingAccounts(true);

        return $provider;
    }

    private function user(string $username): UserEntity
    {
        $user = new UserEntity();
        $user->setId(Uuid::randomHex());
        $user->setUsername($username);
        $user->setEmail($username . '@example.com');
        $user->setAdmin(false);
        $user->setActive(true);

        return $user;
    }

    private function userRepository(): EntityRepository
    {
        $repository = $this->createMock(EntityRepository::class);

        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context): EntitySearchResult {
            $ids = $criteria->getIds();

            if ($ids === []) {
                // findByEmail()
                $users = $this->existingUser === null ? [] : [$this->existingUser];
            } elseif ($this->existingUser !== null && $ids === [$this->existingUser->getId()]) {
                $users = [$this->existingUser];
            } else {
                $id = $ids[0];
                \assert(\is_string($id));
                $user = new UserEntity();
                $user->setId($id);
                $user->setActive(true);
                $users = [$user];
            }

            return new EntitySearchResult(UserDefinition::ENTITY_NAME, \count($users), new UserCollection($users), null, $criteria, $context);
        });

        $repository->method('searchIds')->willReturnCallback(function (Criteria $criteria, Context $context): IdSearchResult {
            foreach ($criteria->getFilters() as $filter) {
                if ($filter instanceof EqualsFilter && $filter->getField() === 'admin') {
                    return $this->idSearchResult($this->otherActiveSuperadmin ? [Uuid::randomHex()] : [], $criteria, $context);
                }
            }

            $username = $this->filterValue($criteria, 'username');
            $ids = \in_array($username, $this->takenUsernames, true) ? [Uuid::randomHex()] : [];

            return $this->idSearchResult($ids, $criteria, $context);
        });

        $repository->method('create')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            array_push($this->userCreates, ...$payload);

            return $this->writtenEvent($context);
        });

        $repository->method('update')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            array_push($this->userUpdates, ...$payload);

            return $this->writtenEvent($context);
        });

        return $repository;
    }

    private function localeRepository(): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('searchIds')->willReturnCallback(function (Criteria $criteria, Context $context): IdSearchResult {
            $code = $this->filterValue($criteria, 'code');

            if ($code === null) {
                return $this->idSearchResult([$this->fallbackLocaleId], $criteria, $context);
            }

            $id = $this->localeIds[$code] ?? null;

            return $this->idSearchResult($id === null ? [] : [$id], $criteria, $context);
        });

        return $repository;
    }

    private function mediaRepository(): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('update')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            array_push($this->mediaUpdates, ...$payload);

            return $this->writtenEvent($context);
        });

        return $repository;
    }

    private function userProviderRepository(): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context): EntitySearchResult {
            $bindings = [];
            $userId = $this->filterValue($criteria, 'userId');
            $sub = $this->filterValue($criteria, 'sub');

            if ($sub !== null) {
                // findUserIdBySubject()
                if ($this->boundProviderId !== null
                    && $this->boundSub === $sub
                    && $this->filterValue($criteria, 'providerId') === $this->boundProviderId
                    && $this->existingUser !== null) {
                    $bindings[] = $this->binding($this->existingUser->getId());
                }
            } elseif ($this->boundProviderId !== null && $userId !== null) {
                $bindings[] = $this->binding($userId);
            }

            return new EntitySearchResult(
                Sw6OidcUserProviderDefinition::ENTITY_NAME,
                \count($bindings),
                new Sw6OidcUserProviderCollection($bindings),
                null,
                $criteria,
                $context,
            );
        });
        $repository->method('create')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            array_push($this->bindingCreates, ...$payload);

            return $this->writtenEvent($context);
        });

        return $repository;
    }

    private function binding(string $userId): Sw6OidcUserProviderEntity
    {
        \assert($this->boundProviderId !== null);

        $binding = new Sw6OidcUserProviderEntity();
        $binding->setId(Uuid::randomHex());
        $binding->setUserType(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN);
        $binding->setUserId($userId);
        $binding->setProviderId($this->boundProviderId);
        $binding->setSub($this->boundSub);

        return $binding;
    }

    private function writtenEvent(Context $context): EntityWrittenContainerEvent
    {
        return new EntityWrittenContainerEvent($context, new NestedEventCollection(), []);
    }

    private function filterValue(Criteria $criteria, string $field): ?string
    {
        foreach ($criteria->getFilters() as $filter) {
            if ($filter instanceof EqualsFilter && $filter->getField() === $field) {
                $value = $filter->getValue();

                return \is_string($value) ? $value : null;
            }
        }

        return null;
    }

    /**
     * @param string[] $ids
     */
    private function idSearchResult(array $ids, Criteria $criteria, Context $context): IdSearchResult
    {
        return new IdSearchResult(
            \count($ids),
            array_map(static fn (string $id): array => ['primaryKey' => $id, 'data' => []], $ids),
            $criteria,
            $context,
        );
    }
}
