<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialCollection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialEntity;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Shopware\Core\Framework\Uuid\Uuid;
use Webauthn\CredentialRecord;

/**
 * Persists WebAuthn credentials to sw6oidc_passkey_credential — the sole seam
 * between web-auth/webauthn-lib's CredentialRecord objects and our DAL
 * storage.
 *
 * webauthn-lib 5.x has no repository contract of its own: the ceremony
 * services look a record up here, hand it to the validator's check(), and
 * persist the returned (counter-bumped) record back via updateAfterAssertion().
 *
 * public_key holds the library's own normalized CredentialRecord JSON. Rows
 * written by the former 4.x PublicKeyCredentialSource::jsonSerialize() have
 * the same shape (base64url ids, {"type": EmptyTrustPath} trust path) and
 * deserialize unchanged.
 */
class PasskeyCredentialRepository
{
    /**
     * @param EntityRepository<Sw6OidcPasskeyCredentialCollection> $passkeyCredentialRepository
     */
    public function __construct(
        private readonly EntityRepository $passkeyCredentialRepository,
        private readonly WebauthnCeremonyFactory $ceremonyFactory,
        private readonly LoggerInterface $logger,
        private readonly Connection $connection,
    ) {
    }

    /**
     * Credentials are looked up and deduplicated by the sha256 of their
     * base64 id: the column is too wide for a unique index and its
     * case-insensitive collation can't compare base64 reliably.
     */
    public static function hashCredentialId(string $base64CredentialId): string
    {
        return hash('sha256', $base64CredentialId);
    }

    /**
     * Disables a credential (possible clone: its signature counter went
     * backwards). It can no longer be used to log in; the owner has to
     * register a new one.
     */
    public function disable(string $base64CredentialId): void
    {
        $entity = $this->findEntityByCredentialId($base64CredentialId);

        if ($entity instanceof Sw6OidcPasskeyCredentialEntity && !$entity->getDisabledAt() instanceof \DateTimeInterface) {
            $this->passkeyCredentialRepository->update([[
                'id' => $entity->getId(),
                'disabledAt' => new \DateTimeImmutable(),
            ]], $this->context());
        }
    }


    /**
     * @param string $userHandle      raw WebAuthn user handle bytes
     * @param bool   $includeDisabled registration's excludeCredentials lists disabled keys too
     *                                (so they aren't re-registered); logins must not offer them
     *
     * @return CredentialRecord[]
     */
    public function findAllForUserHandle(string $userHandle, bool $includeDisabled = true): array
    {
        // The library's user handle is raw bytes; stored/compared as hex since
        // a varchar column can't safely round-trip arbitrary binary data.
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userHandle', bin2hex($userHandle)));

        if (!$includeDisabled) {
            $criteria->addFilter(new EqualsFilter('disabledAt', null));
        }

        $records = [];

        foreach ($this->passkeyCredentialRepository->search($criteria, $this->context())->getEntities() as $entity) {
            $records[] = $this->toRecord($entity);
        }

        return $records;
    }

    /**
     * How many passkeys (disabled ones included) carry this user handle,
     * without deserializing them.
     */
    public function countForUserHandle(string $userHandle): int
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userHandle', bin2hex($userHandle)));

        return $this->passkeyCredentialRepository->search($criteria, $this->context())->getEntities()->count();
    }

    /**
     * Persists the record a successful assertion check() returned (the
     * library bumps the counter and backup flags but, unlike 4.x, no longer
     * saves it) for the credential the caller already loaded. The write is a
     * compare-and-set on the counter: of two concurrent assertions only the
     * higher counter lands, so the counter can never go backwards (R3-L15).
     * Authenticators without a counter (always 0) are always written.
     */
    public function updateAfterAssertion(Sw6OidcPasskeyCredentialEntity $entity, CredentialRecord $record): void
    {
        $updated = $this->connection->executeStatement(
            'UPDATE `sw6oidc_passkey_credential`
             SET `public_key` = :publicKey, `sign_count` = :counter, `updated_at` = :now
             WHERE `id` = :id AND (`sign_count` < :counter OR :counter = 0)',
            [
                'publicKey' => $this->toJson($record),
                'counter' => $record->counter,
                'now' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                'id' => Uuid::fromHexToBytes($entity->getId()),
            ],
        );

        if ($updated === 0) {
            $this->logger->info('sw6oidc: a concurrent passkey assertion already stored a higher signature counter.', [
                'credentialId' => $entity->getId(),
            ]);
        }
    }

    public function saveNewCredentialRecord(
        CredentialRecord $record,
        string $userType,
        string $userId,
        ?string $nickname,
    ): void {
        $this->passkeyCredentialRepository->create([[
            'id' => Uuid::randomHex(),
            'userType' => $userType,
            'userId' => $userId,
            'credentialId' => base64_encode($record->publicKeyCredentialId),
            'credentialIdHash' => self::hashCredentialId(base64_encode($record->publicKeyCredentialId)),
            'publicKey' => $this->toJson($record),
            'signCount' => $record->counter,
            'userHandle' => bin2hex($record->userHandle),
            'nickname' => $nickname,
        ]], $this->context());
    }

    /**
     * Self-service listing for the "My passkeys" section on a user's own
     * profile page — deliberately separate from findAllForUserHandle(),
     * which takes the library's opaque WebAuthn user handle; this one is
     * keyed by our own userType/userId so callers never need to recompute
     * that handle just to list what a user already owns.
     *
     * @return Sw6OidcPasskeyCredentialEntity[]
     */
    public function findAllForOwner(string $userType, string $userId, Context $context): array
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->addFilter(new EqualsFilter('userId', $userId));
        $criteria->addSorting(new FieldSorting('createdAt', FieldSorting::DESCENDING));

        return array_values(array_filter(
            iterator_to_array($this->passkeyCredentialRepository->search($criteria, $context)->getEntities()),
            static fn (\Shopware\Core\Framework\DataAbstractionLayer\Entity $entity): bool => $entity instanceof Sw6OidcPasskeyCredentialEntity,
        ));
    }

    /**
     * Whether at least one passkey credential of this type exists anywhere -
     * lets a login screen gate its "Login with Passkey" button on something
     * a not-yet-identified visitor could actually use, rather than only on
     * PasskeyConfig::isEnabledForAdmin()/isEnabledForCustomer(), which just
     * reflect the feature's on/off toggle regardless of whether anyone has
     * actually registered a credential yet.
     */
    public function existsForUserType(string $userType, Context $context): bool
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->setLimit(1);

        return $this->passkeyCredentialRepository->search($criteria, $context)->first() !== null;
    }

    /**
     * Deletes a credential only if it actually belongs to the given owner —
     * self-service delete must never let a user remove another user's
     * passkey merely by guessing/enumerating an id, so ownership is checked
     * here rather than trusting the caller (unlike the cross-user recovery
     * grid in Settings, which is gated on the entity's own ACL privilege
     * instead).
     */
    public function deleteOwnedByUser(string $id, string $userType, string $userId, Context $context): bool
    {
        // A malformed id from the request is "not found", not a Criteria error (R3-L16).
        if (!Uuid::isValid($id)) {
            return false;
        }

        $criteria = new Criteria([$id]);
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->addFilter(new EqualsFilter('userId', $userId));

        if ($this->passkeyCredentialRepository->search($criteria, $context)->first() === null) {
            return false;
        }

        $this->passkeyCredentialRepository->delete([['id' => $id]], $context);

        return true;
    }

    public function findEntityByCredentialId(string $base64CredentialId): ?Sw6OidcPasskeyCredentialEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('credentialIdHash', self::hashCredentialId($base64CredentialId)));
        $criteria->setLimit(1);

        $entity = $this->passkeyCredentialRepository->search($criteria, $this->context())->first();

        return $entity instanceof Sw6OidcPasskeyCredentialEntity ? $entity : null;
    }

    public function toRecord(Sw6OidcPasskeyCredentialEntity $entity): CredentialRecord
    {
        return $this->ceremonyFactory->serializer()->deserialize($entity->getPublicKey(), CredentialRecord::class, 'json');
    }

    public function toJson(CredentialRecord $record): string
    {
        return $this->ceremonyFactory->serializer()->serialize($record, 'json');
    }

    private function context(): Context
    {
        return Context::createDefaultContext();
    }
}
