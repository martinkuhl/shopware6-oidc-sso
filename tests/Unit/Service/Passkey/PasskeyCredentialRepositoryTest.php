<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialCollection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialEntity;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Passkey\WebauthnCeremonyFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

#[CoversClass(PasskeyCredentialRepository::class)]
final class PasskeyCredentialRepositoryTest extends TestCase
{
    /**
     * A public_key value exactly as webauthn-lib 4.9's
     * PublicKeyCredentialSource::jsonSerialize() stored it (public key
     * material only) — must still deserialize after the 5.x migration.
     */
    private const LEGACY_4X_PUBLIC_KEY = '{"publicKeyCredentialId":"OqgFHZhKQWaxLK8ZEvagkw","type":"public-key","transports":[],"attestationType":"none","trustPath":{"type":"Webauthn\\\\TrustPath\\\\EmptyTrustPath"},"aaguid":"d548826e-79b4-db40-a3d8-11116f7e8349","credentialPublicKey":"pQECAyYgASFYIBh2IVA9JOGag_dFVuLV8s_TlqOWKaw_K23SCLlGDSIXIlggEyJ6eoq3RfZGfw94vtDmvhhJJd0JQ3jouC6xXJT9P-c","userHandle":"ZAzT6hkL9_gnPQspFSBDWdo_YSAsIguSHMgxav-jiSI","counter":0,"backupEligible":true,"backupStatus":true}';

    private InMemoryPasskeyCredentialStore $store;

    private PasskeyCredentialRepository $repository;

    protected function setUp(): void
    {
        $this->store = new InMemoryPasskeyCredentialStore();
        $this->repository = new PasskeyCredentialRepository(
            $this->store->wire($this->createMock(EntityRepository::class)),
            new WebauthnCeremonyFactory(),
            new NullLogger(),
            $this->store->connection($this->createMock(Connection::class)),
        );
    }

    /**
     * R8-M8: "My passkeys" needs only "update own profile"; the owner check
     * is the authorisation, so the DAL calls must not run with the caller's
     * ACL (core would demand sw6oidc_passkey_credential:read/delete).
     */
    public function testSelfServiceCallsRunWithoutTheCallersAcl(): void
    {
        $id = Uuid::randomHex();
        $userId = Uuid::randomHex();
        $notAnAdminSource = self::callback(static fn (Context $context): bool => !$context->getSource() instanceof AdminApiSource);

        $entity = new Sw6OidcPasskeyCredentialEntity();
        $entity->setId($id);
        $dal = $this->createMock(EntityRepository::class);
        $dal->expects(self::exactly(2))->method('search')->with(self::anything(), $notAnAdminSource)
            ->willReturnCallback(static fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
                'sw6oidc_passkey_credential',
                1,
                new Sw6OidcPasskeyCredentialCollection([$entity]),
                null,
                $criteria,
                $context,
            ));
        $dal->expects(self::once())->method('delete')->with([['id' => $id]], $notAnAdminSource);

        $repository = new PasskeyCredentialRepository($dal, new WebauthnCeremonyFactory(), new NullLogger(), $this->createMock(Connection::class));

        self::assertCount(1, $repository->findAllForOwner('admin', $userId));
        self::assertTrue($repository->deleteOwnedByUser($id, 'admin', $userId));
    }

    public function testLegacy4xStoredCredentialDeserializes(): void
    {
        $rawId = (string) base64_decode('OqgFHZhKQWaxLK8ZEvagkw==', true);
        $this->addLegacyRow($rawId);

        $record = $this->record($rawId);

        self::assertNotNull($record);
        self::assertSame($rawId, $record->publicKeyCredentialId);
        self::assertSame('none', $record->attestationType);
        self::assertInstanceOf(EmptyTrustPath::class, $record->trustPath);
        self::assertSame(SoftwareAuthenticator::unb64('ZAzT6hkL9_gnPQspFSBDWdo_YSAsIguSHMgxav-jiSI'), $record->userHandle);
        self::assertTrue($record->backupEligible);
    }

    public function testSerializedRecordRoundTrips(): void
    {
        $rawId = (string) base64_decode('OqgFHZhKQWaxLK8ZEvagkw==', true);
        $this->addLegacyRow($rawId);
        $record = $this->record($rawId);
        self::assertNotNull($record);

        $record->counter = 7;
        $this->repository->updateAfterAssertion($this->entity($rawId), $record);

        $reloaded = $this->record($rawId);
        self::assertNotNull($reloaded);
        self::assertSame(7, $reloaded->counter);
        self::assertSame($record->credentialPublicKey, $reloaded->credentialPublicKey);
        self::assertSame(7, $this->store->rows[array_key_first($this->store->rows)]['signCount']);
    }

    public function testFindAllForUserHandleMatchesByHexHandle(): void
    {
        $rawId = (string) base64_decode('OqgFHZhKQWaxLK8ZEvagkw==', true);
        $this->addLegacyRow($rawId);

        $handle = SoftwareAuthenticator::unb64('ZAzT6hkL9_gnPQspFSBDWdo_YSAsIguSHMgxav-jiSI');

        self::assertCount(1, $this->repository->findAllForUserHandle($handle));
        self::assertSame([], $this->repository->findAllForUserHandle(random_bytes(32)));
    }

    public function testUpdateAfterAssertionIgnoresUnknownCredential(): void
    {
        $rawId = (string) base64_decode('OqgFHZhKQWaxLK8ZEvagkw==', true);
        $this->addLegacyRow($rawId);
        $record = $this->record($rawId);
        self::assertNotNull($record);
        $entity = $this->entity($rawId);
        $this->store->rows = [];

        // Deleted meanwhile: the update matches nothing and recreates nothing.
        $this->repository->updateAfterAssertion($entity, $record);

        self::assertSame([], $this->store->rows);
    }

    public function testALowerCounterNeverOverwritesAHigherOne(): void
    {
        $rawId = (string) base64_decode('OqgFHZhKQWaxLK8ZEvagkw==', true);
        $this->addLegacyRow($rawId);
        $entity = $this->entity($rawId);
        $record = $this->record($rawId);
        self::assertNotNull($record);

        // Two concurrent assertions: counter 9 is stored first, then 8 (R3-L15).
        $record->counter = 9;
        $this->repository->updateAfterAssertion($entity, $record);
        $record->counter = 8;
        $this->repository->updateAfterAssertion($entity, $record);

        self::assertSame(9, $this->store->rows[array_key_first($this->store->rows)]['signCount']);
    }

    private function record(string $rawId): ?CredentialRecord
    {
        $entity = $this->repository->findEntityByCredentialId(base64_encode($rawId));

        return $entity instanceof Sw6OidcPasskeyCredentialEntity ? $this->repository->toRecord($entity) : null;
    }

    private function entity(string $rawId): Sw6OidcPasskeyCredentialEntity
    {
        $entity = $this->repository->findEntityByCredentialId(base64_encode($rawId));
        self::assertInstanceOf(Sw6OidcPasskeyCredentialEntity::class, $entity);

        return $entity;
    }

    private function addLegacyRow(string $rawId): void
    {
        $this->store->add([
            'id' => Uuid::randomHex(),
            'userType' => 'customer',
            'userId' => Uuid::randomHex(),
            'credentialId' => base64_encode($rawId),
            'publicKey' => self::LEGACY_4X_PUBLIC_KEY,
            'userHandle' => bin2hex(SoftwareAuthenticator::unb64('ZAzT6hkL9_gnPQspFSBDWdo_YSAsIguSHMgxav-jiSI')),
        ]);
    }
}
