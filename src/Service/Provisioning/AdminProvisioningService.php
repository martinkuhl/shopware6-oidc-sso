<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AdminAfterCreateEvent;
use MartinKuhl\Sw6Oidc\Event\AdminBeforeCreateEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AdminProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Content\Media\MediaCollection;
use Shopware\Core\Content\Media\MediaService;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityCollection;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\Locale\LocaleCollection;
use Shopware\Core\System\User\UserCollection;
use Shopware\Core\System\User\UserEntity;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Finds-or-JIT-creates a Shopware Administration `user` from a MappedProfile,
 * with ACL role mapping, role/profile sync and per-user IdP binding.
 *
 * Role sync only adds and removes the roles it granted itself
 * (`sw6oidc_managed_acl_role`): roles granted by hand in Shopware survive
 * every login (R3-M11).
 */
class AdminProvisioningService
{
    private const MAX_USERNAME_SUFFIX = 3;

    /** user.customFields key: sha256 of the picture URL last imported (M19). */
    public const AVATAR_URL_HASH_FIELD = 'sw6oidc_avatar_url_hash';

    /**
     * @param EntityRepository<EntityCollection<Entity>> $aclUserRoleRepository
     * @param EntityRepository<LocaleCollection> $localeRepository
     * @param EntityRepository<MediaCollection> $mediaRepository
     * @param EntityRepository<UserCollection> $userRepository
     */
    public function __construct(
        private readonly EntityRepository $userRepository,
        private readonly EntityRepository $localeRepository,
        private readonly EntityRepository $mediaRepository,
        private readonly GroupMappingResolver $groupMappingResolver,
        private readonly UserProviderBindingService $bindingService,
        private readonly IdentityResolver $identityResolver,
        private readonly MediaService $mediaService,
        private readonly AvatarFetcher $avatarFetcher,
        private readonly TimeZoneValidator $timeZoneValidator,
        private readonly LoggerInterface $logger,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly EntityRepository $aclUserRoleRepository,
        private readonly Connection $connection,
        private readonly AdminRoleStore $roleStore,
    ) {
    }

    /**
     * @throws AdminProvisioningDeniedException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException
     */
    public function findOrCreateAdmin(Sw6OidcProviderEntity $provider, MappedProfile $profile, ExternalIdentity $identity, Context $context): UserEntity
    {
        $emailMatch = $this->findByEmail($profile->email, $context);

        $userId = $this->identityResolver->resolve(
            Sw6OidcUserProviderEntity::USER_TYPE_ADMIN,
            $provider,
            $identity,
            $emailMatch?->getId(),
            // Every admin is privileged: an all-powerful ACL role is as
            // dangerous as the superadmin flag (R3-M10, R3-L23).
            $emailMatch instanceof UserEntity,
            $context,
        );

        if ($userId !== null) {
            $existing = $this->existingAdmin($userId, $emailMatch, $context);

            // An inactive account can't log in anyway (AdminOidcGrant refuses
            // it): no sync, registry entry or nonce for it (R3-L28).
            if (!$existing->getActive()) {
                throw AdminProvisioningDeniedException::accountInactive();
            }

            return $this->syncExisting($provider, $existing, $profile, $context);
        }

        if (!$provider->isAutoCreateAdmin()) {
            throw AdminProvisioningDeniedException::autoCreateDisabled();
        }

        $isSuperadmin = $provider->isAllowSuperadminGroupMapping()
            && $this->groupMappingResolver->matchesSuperadminGroup($provider, $profile->groups, $context);

        $mappedRoleIds = [];
        $aclRoleIds = [];

        if (!$isSuperadmin) {
            $mappedRoleIds = $this->groupMappingResolver->resolveAclRoleIds($provider, $profile->groups, $context);
            // The provider default applies to new accounts only (R3-M11).
            $defaultRoleId = $provider->getDefaultAclRoleId();
            $aclRoleIds = $mappedRoleIds !== [] ? $mappedRoleIds : ($defaultRoleId !== null ? [$defaultRoleId] : []);

            if ($aclRoleIds === []) {
                throw AdminProvisioningDeniedException::noRoleResolved();
            }
        }

        try {
            // Create and bind together: a concurrent first login of the same
            // subject must not leave an unbound duplicate behind (R3-M12).
            $userId = $this->connection->transactional(function () use ($provider, $profile, $aclRoleIds, $mappedRoleIds, $isSuperadmin, $identity, $context): string {
                $userId = $this->create($provider, $profile, $aclRoleIds, $isSuperadmin, $context);
                $this->roleStore->rememberManaged($userId, $mappedRoleIds, $provider->getId());
                $this->bindingService->bind(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $userId, $identity, $context);

                return $userId;
            });
        } catch (UniqueConstraintViolationException | SubjectAlreadyLinkedException | ProviderMismatchException $exception) {
            $winnerId = $this->bindingService->findUserIdBySubject(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $identity, $context);

            if ($winnerId === null) {
                throw $exception;
            }

            $this->logger->info('sw6oidc: concurrent first login; using the account the other login created.', [
                'providerId' => $provider->getId(),
                'userId' => $winnerId,
            ]);

            return $this->existingAdmin($winnerId, null, $context);
        }

        // Outside the transaction: the media file can't be rolled back.
        if ($profile->picture !== null) {
            $avatarPayload = $this->syncAvatar($userId, $profile->picture, null, $context);

            if ($avatarPayload !== []) {
                $this->userRepository->update([['id' => $userId, ...$avatarPayload]], $context);
            }
        }

        $created = $this->userRepository->search(new Criteria([$userId]), $context)->first();
        \assert($created instanceof UserEntity);

        $this->eventDispatcher->dispatch(new AdminAfterCreateEvent($provider, $profile, $created, $context));

        return $created;
    }

    private function existingAdmin(string $userId, ?UserEntity $emailMatch, Context $context): UserEntity
    {
        $existing = $emailMatch instanceof UserEntity && $emailMatch->getId() === $userId
            ? $emailMatch
            : $this->userRepository->search(new Criteria([$userId]), $context)->first();

        if (!$existing instanceof UserEntity) {
            throw AdminProvisioningDeniedException::accountMissing();
        }

        return $existing;
    }

    private function syncExisting(Sw6OidcProviderEntity $provider, UserEntity $existing, MappedProfile $profile, Context $context): UserEntity
    {
        if ($provider->isSyncAdminRoleOnSso()) {
            $this->syncRole($provider, $existing, $profile->groups, $context);
        }

        if ($provider->isSyncAdminProfileOnSso()) {
            $this->syncProfile($existing, $profile, $context);
        }

        return $existing;
    }

    private function findByEmail(string $email, Context $context): ?UserEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('email', $email));
        $criteria->setLimit(1);

        $user = $this->userRepository->search($criteria, $context)->first();
        \assert($user === null || $user instanceof UserEntity);

        return $user;
    }

    /**
     * @param list<string> $aclRoleIds
     */
    private function create(Sw6OidcProviderEntity $provider, MappedProfile $profile, array $aclRoleIds, bool $isSuperadmin, Context $context): string
    {
        $userId = Uuid::randomHex();

        $payload = [
            'id' => $userId,
            'localeId' => $this->resolveLocaleId($profile->locale, $context),
            'username' => $this->resolveUniqueUsername($profile, $context),
            // Never the email address itself as a name (L9).
            'firstName' => $profile->firstName ?? (trim(explode('@', $profile->email)[0]) ?: '-'),
            'lastName' => $profile->lastName ?? '-',
            'email' => $profile->email,
            'password' => bin2hex(random_bytes(32)),
            'active' => true,
            'admin' => $isSuperadmin,
            'aclRoles' => $isSuperadmin ? [] : array_map(static fn (string $roleId): array => ['id' => $roleId], $aclRoleIds),
        ];

        $timeZone = $this->resolveTimeZone($profile->zoneinfo);

        if ($timeZone !== null) {
            $payload['timeZone'] = $timeZone;
        }

        $event = new AdminBeforeCreateEvent($provider, $profile, $payload, $context);
        $this->eventDispatcher->dispatch($event);
        $payload = $this->recheckListenerPayload($provider, $payload, [...$event->getPayload(), 'id' => $userId]);

        $this->createWithUniqueUsername($payload, $profile, $context);

        $this->logger->info('sw6oidc: JIT-created Administration user via OIDC.', [
            'providerId' => $provider->getId(),
            'userId' => $userId,
            'superadmin' => (bool) ($payload['admin'] ?? false),
        ]);

        return $userId;
    }

    /**
     * AdminBeforeCreateEvent listeners are trusted code, but an escalation
     * they cause must never be silent: log a superadmin grant or role change
     * the provider's own mapping did not decide, and never let the email
     * drift from the verified claim.
     *
     * @param array<string, mixed> $original
     * @param array<string, mixed> $changed
     *
     * @return array<string, mixed>
     */
    private function recheckListenerPayload(Sw6OidcProviderEntity $provider, array $original, array $changed): array
    {
        if (($changed['email'] ?? null) !== $original['email']) {
            $this->logger->warning('sw6oidc: AdminBeforeCreateEvent listener changed the email; the verified claim is kept.', [
                'providerId' => $provider->getId(),
            ]);
            $changed['email'] = $original['email'];
        }

        if ((bool) ($changed['admin'] ?? false) && !(bool) $original['admin']) {
            $this->logger->warning('sw6oidc: AdminBeforeCreateEvent listener granted superadmin outside the provider group mapping.', [
                'providerId' => $provider->getId(),
                'userId' => $original['id'],
            ]);
        }

        if (($changed['aclRoles'] ?? null) != $original['aclRoles']) {
            $this->logger->warning('sw6oidc: AdminBeforeCreateEvent listener changed the ACL roles.', [
                'providerId' => $provider->getId(),
                'userId' => $original['id'],
            ]);
        }

        return $changed;
    }

    /**
     * The username is unique; two concurrent first logins can derive the same
     * one. Retry with a fresh suffix instead of failing the login. Any other
     * unique violation (the email) is a concurrent login of the same person:
     * rethrown, so the caller re-resolves (R3-M12).
     *
     * @param array<string, mixed> $payload
     */
    private function createWithUniqueUsername(array $payload, MappedProfile $profile, Context $context): void
    {
        for ($attempt = 0;; ++$attempt) {
            try {
                $this->userRepository->create([$payload], $context);

                return;
            } catch (UniqueConstraintViolationException $exception) {
                if ($attempt >= 2 || !str_contains($exception->getMessage(), 'username')) {
                    throw $exception;
                }

                $payload['username'] = $this->resolveUniqueUsername($profile, $context) . '-' . bin2hex(random_bytes(2));
            }
        }
    }

    /**
     * Makes the admin's permissions follow the IdP groups of this login:
     *
     * - A superadmin group match (two gates: provider flag + explicit
     *   mapping row) grants superadmin.
     * - Otherwise every role a mapping grants is added, and roles the plugin
     *   granted earlier (`sw6oidc_managed_acl_role`) that no group grants any
     *   more are removed. Roles granted by hand are never touched, and the
     *   provider default never applies here (R3-M11, H3).
     * - Superadmin is revoked only with the provider's
     *   `revoke_superadmin_on_sso` opt-in — also when no group resolves at
     *   all — and never from the last active superadmin.
     *
     * @param string[] $groups
     */
    private function syncRole(Sw6OidcProviderEntity $provider, UserEntity $user, array $groups, Context $context): void
    {
        $userId = $user->getId();

        if ($provider->isAllowSuperadminGroupMapping() && $this->groupMappingResolver->matchesSuperadminGroup($provider, $groups, $context)) {
            if (!$user->isAdmin()) {
                $this->userRepository->update([['id' => $userId, 'admin' => true]], $context);
            }

            return;
        }

        $mapped = $this->groupMappingResolver->resolveAclRoleIds($provider, $groups, $context);
        $current = $this->roleStore->roleIds($userId);
        $managed = $this->roleStore->managedRoleIds($userId);

        $toAdd = array_values(array_diff($mapped, $current));
        $toRemove = array_values(array_intersect(array_diff($managed, $mapped), $current));
        // Managed roles someone removed by hand: forget them.
        $forget = array_values(array_diff($managed, $mapped));

        if ($toAdd !== []) {
            $this->userRepository->update([['id' => $userId, 'aclRoles' => array_map(static fn (string $roleId): array => ['id' => $roleId], $toAdd)]], $context);
            $this->roleStore->rememberManaged($userId, $toAdd, $provider->getId());
        }

        if ($toRemove !== []) {
            $this->aclUserRoleRepository->delete(array_map(static fn (string $roleId): array => ['userId' => $userId, 'aclRoleId' => $roleId], $toRemove), $context);
        }

        $this->roleStore->forgetManaged($userId, $forget);

        if ($user->isAdmin() && $provider->isRevokeSuperadminOnSso()) {
            $this->revokeSuperadmin($provider, $userId, $context);
        }

        if ($toAdd !== [] || $toRemove !== []) {
            $this->logger->info('sw6oidc: admin roles synced from IdP groups.', [
                'providerId' => $provider->getId(),
                'userId' => $userId,
                'addedRoles' => \count($toAdd),
                'removedRoles' => \count($toRemove),
            ]);
        }
    }

    /**
     * Never the last active superadmin; the check and the revoke can't race
     * (AdminRoleStore, R3-M11).
     */
    private function revokeSuperadmin(Sw6OidcProviderEntity $provider, string $userId, Context $context): void
    {
        $revoked = $this->roleStore->revokeSuperadminUnlessLast(
            $userId,
            fn (): EntityWrittenContainerEvent => $this->userRepository->update([['id' => $userId, 'admin' => false]], $context),
        );

        if (!$revoked) {
            $this->logger->warning('sw6oidc: superadmin not revoked by role sync — this is the last active superadmin.', [
                'providerId' => $provider->getId(),
                'userId' => $userId,
            ]);

            return;
        }

        $this->logger->warning('sw6oidc: superadmin revoked by role sync (IdP groups no longer grant it).', [
            'providerId' => $provider->getId(),
            'userId' => $userId,
        ]);
    }
    /**
     * Partial update only — a claim that isn't mapped (null on the profile)
     * is left alone rather than overwritten, same rationale as
     * CustomerProvisioningService::syncExisting(). Administration users
     * have no birthday/gender/salutation fields, unlike customers, so this
     * only touches first/last name plus locale/timezone/avatar.
     */
    private function syncProfile(UserEntity $existing, MappedProfile $profile, Context $context): void
    {
        $userId = $existing->getId();
        $payload = ['id' => $userId];

        if ($profile->firstName !== null) {
            $payload['firstName'] = $profile->firstName;
        }

        if ($profile->lastName !== null) {
            $payload['lastName'] = $profile->lastName;
        }

        if ($profile->locale !== null) {
            $payload['localeId'] = $this->resolveLocaleId($profile->locale, $context);
        }

        $timeZone = $this->resolveTimeZone($profile->zoneinfo);

        if ($timeZone !== null) {
            $payload['timeZone'] = $timeZone;
        }

        if ($profile->picture !== null) {
            // The entity loaded by findOrCreateAdmin(): no second query (L8).
            $payload = [...$payload, ...$this->syncAvatar($userId, $profile->picture, $existing, $context)];
        }

        // Most logins change nothing: no write, so no user.written events (R3-L29).
        $current = $existing->getVars();

        foreach (['firstName', 'lastName', 'localeId', 'timeZone'] as $field) {
            if (\array_key_exists($field, $payload) && \array_key_exists($field, $current) && $payload[$field] === $current[$field]) {
                unset($payload[$field]);
            }
        }

        if (\count($payload) > 1) {
            $this->userRepository->update([$payload], $context);
        }
    }

    /**
     * Fetches the picture claim's URL (AvatarFetcher, SSRF-guarded) and
     * imports it as (or overwrites) the user's avatar Media entity. Skipped
     * when the URL's hash matches the one stored in the user's custom fields
     * at the last import and the avatar still exists (M19). A bad or
     * unreachable picture claim must never break login, so any failure is
     * logged and swallowed and the previous avatar stays.
     *
     * Uses Shopware core's own 'user' default media folder (seeded by
     * BasicData's `avatarUser` association) rather than leaving the Media
     * row unassigned — same folder a manually-uploaded avatar would land
     * in, so it gets the same thumbnail-size config.
     *
     * Media is always forced public (`private: false`): a `private` Media
     * entity is only servable through an authenticated download action,
     * not a plain `<img src>`, so a private avatar would never render
     * anywhere in the Administration UI. The explicit follow-up update
     * covers both a brand-new Media row and one from a previous sync that
     * was created private, self-healing on the next login rather than
     * requiring a one-off manual fix.
     *
     * @return array<string, mixed> user update fields (empty = nothing to write)
     */
    private function syncAvatar(string $userId, string $pictureUrl, ?UserEntity $existing, Context $context): array
    {
        $existingAvatarId = $existing?->getAvatarId();
        $urlHash = hash('sha256', $pictureUrl);

        if ($existingAvatarId !== null && ($existing?->getCustomFields()[self::AVATAR_URL_HASH_FIELD] ?? null) === $urlHash) {
            return [];
        }

        $tempFile = tempnam(sys_get_temp_dir(), 'sw6oidc_avatar_');

        if ($tempFile === false) {
            return [];
        }

        try {
            $mediaFile = $this->avatarFetcher->fetch($pictureUrl, $tempFile);

            $avatarId = $this->mediaService->saveMediaFile(
                $mediaFile,
                'sw6oidc-avatar-' . $userId,
                $context,
                'user',
                $existingAvatarId,
                false,
            );

            $this->mediaRepository->update([['id' => $avatarId, 'private' => false]], $context);

            $this->logger->info('sw6oidc: imported Administration user avatar from picture claim.', [
                'userId' => $userId,
                'avatarId' => $avatarId,
                'mimeType' => $mediaFile->getMimeType(),
                'fileExtension' => $mediaFile->getFileExtension(),
                'fileSize' => $mediaFile->getFileSize(),
            ]);

            return ['avatarId' => $avatarId, 'customFields' => [self::AVATAR_URL_HASH_FIELD => $urlHash]];
        } catch (\Throwable $e) {
            $this->logger->warning('sw6oidc: failed to import Administration user avatar from picture claim.', [
                'userId' => $userId,
                'exception' => $e::class,
                'error' => $e->getMessage(),
            ]);

            return [];
        } finally {
            if (is_file($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    private function resolveUniqueUsername(MappedProfile $profile, Context $context): string
    {
        $base = $profile->username ?? explode('@', $profile->email)[0];
        $base = preg_replace('/[^a-zA-Z0-9._-]/', '', $base) ?: 'user';

        // A few readable candidates, then a random suffix: the number of
        // queries stays bounded however many "jane"s exist (R3-L25).
        for ($suffix = 0; $suffix <= self::MAX_USERNAME_SUFFIX; ++$suffix) {
            $candidate = $suffix === 0 ? $base : $base . $suffix;

            if (!$this->usernameExists($candidate, $context)) {
                return $candidate;
            }
        }

        // The create retry (createWithUniqueUsername) covers the unlikely clash.
        return $base . '-' . bin2hex(random_bytes(2));
    }

    private function usernameExists(string $username, Context $context): bool
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('username', $username));
        $criteria->setLimit(1);

        return $this->userRepository->searchIds($criteria, $context)->getTotal() > 0;
    }

    /**
     * Resolves the `locale` claim (e.g. "de-DE") against an exact `Locale.code`
     * match; falls back to the previous hardcoded "en-GB"-or-first-available
     * behavior when the claim is absent or doesn't match any known locale.
     */
    private function resolveLocaleId(?string $localeClaim, Context $context): string
    {
        if ($localeClaim !== null) {
            $criteria = new Criteria();
            $criteria->addFilter(new EqualsFilter('code', $localeClaim));
            $criteria->setLimit(1);

            $id = $this->localeRepository->searchIds($criteria, $context)->firstId();

            if ($id !== null) {
                return $id;
            }
        }

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('code', 'en-GB'));
        $criteria->setLimit(1);

        $id = $this->localeRepository->searchIds($criteria, $context)->firstId();

        if ($id !== null) {
            return $id;
        }

        $fallback = $this->localeRepository->searchIds(new Criteria(), $context)->firstId();
        \assert($fallback !== null);

        return $fallback;
    }

    /**
     * Validates the `zoneinfo` claim against PHP's known IANA identifiers
     * (the same set Shopware's own TimeZoneFieldSerializer validates
     * against) — returns null (leave the field untouched) for a missing or
     * malformed claim rather than letting the DAL write fail the login.
     */
    private function resolveTimeZone(?string $zoneinfoClaim): ?string
    {
        return $this->timeZoneValidator->isValid($zoneinfoClaim) ? $zoneinfoClaim : null;
    }
}
