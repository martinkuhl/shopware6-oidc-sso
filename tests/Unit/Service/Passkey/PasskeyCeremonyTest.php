<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyCeremonyException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyAuthenticationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyLimitReachedException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRegistrationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingParty;
use MartinKuhl\Sw6Oidc\Service\Passkey\WebauthnCeremonyFactory;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Full registration + login ceremonies against the real webauthn-lib 5.x
 * validators, driven by an in-process software authenticator.
 */
#[CoversClass(PasskeyRegistrationService::class)]
#[CoversClass(PasskeyAuthenticationService::class)]
#[CoversClass(WebauthnCeremonyFactory::class)]
final class PasskeyCeremonyTest extends TestCase
{
    private InMemoryPasskeyCredentialStore $store;

    private PasskeyCredentialRepository $credentials;

    private PasskeyRegistrationService $registration;

    private PasskeyAuthenticationService $authentication;

    private SoftwareAuthenticator $authenticator;

    private string $userId;

    protected function setUp(): void
    {
        $factory = new WebauthnCeremonyFactory();
        $cache = new InMemoryAtomicCache();
        $this->store = new InMemoryPasskeyCredentialStore();
        $this->credentials = new PasskeyCredentialRepository($this->store->wire($this->createMock(EntityRepository::class)), $factory, new NullLogger(), $this->store->connection($this->createMock(Connection::class)));
        $this->registration = new PasskeyRegistrationService($factory, $this->credentials, $cache);
        $this->authentication = new PasskeyAuthenticationService($factory, $this->credentials, $cache);
        $this->authenticator = new SoftwareAuthenticator();
        $this->userId = Uuid::randomHex();
    }

    public function testCreationOptionsAreBase64UrlWithoutNulls(): void
    {
        $options = $this->creationOptions();

        self::assertSame(32, \strlen(SoftwareAuthenticator::unb64($options['challenge'])));
        self::assertSame(hash('sha256', 'admin:' . $this->userId, true), SoftwareAuthenticator::unb64($options['user']['id']));
        self::assertSame('shop.example', $options['rp']['id']);
        self::assertStringNotContainsString('null', json_encode($options, \JSON_THROW_ON_ERROR));
    }

    public function testRegistrationPersistsCredential(): void
    {
        $this->register();

        self::assertCount(1, $this->store->rows);
        $row = array_values($this->store->rows)[0];
        self::assertSame('admin', $row['userType']);
        self::assertSame($this->userId, $row['userId']);
        self::assertSame(base64_encode($this->authenticator->credentialId), $row['credentialId']);
        self::assertSame('My key', $row['nickname']);
    }

    public function testRegisteredCredentialIsExcludedFromNextRegistration(): void
    {
        $this->register();

        $options = $this->creationOptions();

        self::assertCount(1, $options['excludeCredentials']);
        self::assertSame($this->authenticator->credentialId, SoftwareAuthenticator::unb64($options['excludeCredentials'][0]['id']));
    }

    public function testUsernamelessLoginResolvesOwnerAndPersistsCounter(): void
    {
        $this->register();

        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);
        $assertion = $this->authenticator->assert($options, hash('sha256', 'admin:' . $this->userId, true));

        $resolved = $this->authentication->verifyAssertion($result['nonce'], $assertion, 'shop.example', 'storefront-login:test');

        self::assertSame('admin', $resolved['userType']);
        self::assertSame($this->userId, $resolved['userId']);
        self::assertSame(1, array_values($this->store->rows)[0]['signCount']);
    }

    public function testEmailScopedLoginWithAllowCredentials(): void
    {
        $this->register();
        $handle = hash('sha256', 'admin:' . $this->userId, true);
        $allow = array_map(static fn ($record) => $record->getPublicKeyCredentialDescriptor(), $this->credentials->findAllForUserHandle($handle));

        $result = $this->authentication->buildRequestOptions($allow, $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);
        self::assertCount(1, $options['allowCredentials']);

        $resolved = $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, $handle), 'shop.example', 'storefront-login:test');

        self::assertSame($this->userId, $resolved['userId']);
    }

    /**
     * R3-M7: a Storefront ceremony can't be redeemed at the Administration's
     * login, even when one RP ID covers both hosts.
     */
    public function testCeremonyOnlyCompletesForItsPurpose(): void
    {
        $this->register();
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);

        $this->expectException(PasskeyCeremonyException::class);
        $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, hash('sha256', 'admin:' . $this->userId, true)), 'shop.example', 'admin-login');
    }

    public function testLoginNonceIsSingleUse(): void
    {
        $this->register();
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);
        $handle = hash('sha256', 'admin:' . $this->userId, true);

        $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, $handle), 'shop.example', 'storefront-login:test');

        $this->expectException(PasskeyCeremonyException::class);
        $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, $handle), 'shop.example', 'storefront-login:test');
    }

    public function testUnregisteredCredentialIsRejected(): void
    {
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);

        $this->expectException(PasskeyCeremonyException::class);
        $this->expectExceptionMessage('not registered');
        $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, random_bytes(32)), 'shop.example', 'storefront-login:test');
    }

    public function testWrongHostIsRejected(): void
    {
        $this->register();
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);
        $evil = new SoftwareAuthenticator('https://evil.example');

        $this->expectException(PasskeyCeremonyException::class);
        $this->authentication->verifyAssertion($result['nonce'], $evil->assert($options, random_bytes(32)), 'shop.example', 'storefront-login:test');
    }

    public function testUnknownRegistrationNonceIsRejected(): void
    {
        $this->expectException(PasskeyCeremonyException::class);
        $this->registration->verifyAndPersist('nope', '{}', 'shop.example', null, 'admin', $this->userId);
    }

    public function testRequestOptionsRequireUserVerification(): void
    {
        $options = json_decode($this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test')['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);

        self::assertSame('required', $options['userVerification']);
        self::assertSame('required', $this->creationOptions()['authenticatorSelection']['userVerification']);
    }

    public function testAssertionWithoutUserVerificationIsRejected(): void
    {
        $this->register();
        // The same key, used without PIN/biometrics: possession alone is not enough (H6).
        $this->authenticator->setUserVerified(false);
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);

        $this->expectException(PasskeyCeremonyException::class);
        $this->expectExceptionMessage('User authentication required');
        $this->authentication->verifyAssertion($result['nonce'], $this->authenticator->assert($options, hash('sha256', 'admin:' . $this->userId, true)), 'shop.example', 'storefront-login:test');
    }

    public function testAssertionRelayedThroughASubdomainIsRejected(): void
    {
        $this->register();
        // Same credential and RP ID, but the ceremony ran on another host of the domain (N-M1).
        $relay = new SoftwareAuthenticator('https://blog.shop.example', 'shop.example');
        $result = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $options = json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);

        $this->expectException(PasskeyCeremonyException::class);
        $this->authentication->verifyAssertion($result['nonce'], $relay->assert($options, hash('sha256', 'admin:' . $this->userId, true)), 'blog.shop.example', 'storefront-login:test');
    }

    public function testRegistrationCannotBeCompletedByAnotherAccount(): void
    {
        $options = $this->creationOptions($nonce);

        try {
            $this->registration->verifyAndPersist((string) $nonce, $this->authenticator->register($options), 'shop.example', null, 'admin', Uuid::randomHex());
            self::fail('Expected PasskeyCeremonyException');
        } catch (PasskeyCeremonyException) {
        }

        self::assertSame([], $this->store->rows, 'nothing was planted on the victim account (N-M2)');
    }

    public function testCounterGoingBackwardsDisablesTheCredential(): void
    {
        $this->register();
        $handle = hash('sha256', 'admin:' . $this->userId, true);

        $first = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $this->authentication->verifyAssertion($first['nonce'], $this->authenticator->assert(json_decode($first['optionsJson'], true, 512, \JSON_THROW_ON_ERROR), $handle), 'shop.example', 'storefront-login:test');
        $this->authenticator->rewindCounter(0);

        $second = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');

        try {
            $this->authentication->verifyAssertion($second['nonce'], $this->authenticator->assert(json_decode($second['optionsJson'], true, 512, \JSON_THROW_ON_ERROR), $handle), 'shop.example', 'storefront-login:test');
            self::fail('Expected PasskeyCeremonyException');
        } catch (PasskeyCeremonyException) {
        }

        self::assertNotNull(array_values($this->store->rows)[0]['disabledAt'] ?? null, 'the possible clone was disabled');

        $third = $this->authentication->buildRequestOptions([], $this->rp(), 'storefront-login:test');
        $this->expectException(PasskeyCeremonyException::class);
        $this->expectExceptionMessage('disabled');
        $this->authenticator->rewindCounter(10);
        $this->authentication->verifyAssertion($third['nonce'], $this->authenticator->assert(json_decode($third['optionsJson'], true, 512, \JSON_THROW_ON_ERROR), $handle), 'shop.example', 'storefront-login:test');
    }

    private function rp(): PasskeyRelyingParty
    {
        return new PasskeyRelyingParty('shop.example', 'Shop', ['https://shop.example']);
    }

    public function testRegistrationStopsAtTheCredentialLimit(): void
    {
        $handle = bin2hex(hash('sha256', 'admin:' . $this->userId, true));

        for ($i = 0; $i < PasskeyRegistrationService::MAX_CREDENTIALS_PER_ACCOUNT; ++$i) {
            $this->store->add(['id' => Uuid::randomHex(), 'userType' => 'admin', 'userId' => $this->userId, 'credentialId' => base64_encode(random_bytes(16)), 'publicKey' => '{}', 'userHandle' => $handle]);
        }

        // R3-L13: no unbounded number of keys per account.
        $this->expectException(PasskeyLimitReachedException::class);

        $this->creationOptions();
    }

    /**
     * @param-out string $nonce
     *
     * @return array<string, mixed>
     */
    private function creationOptions(?string &$nonce = null): array
    {
        $result = $this->registration->buildCreationOptions('admin', $this->userId, 'admin', 'Admin', $this->rp());
        $nonce = $result['nonce'];

        return json_decode($result['optionsJson'], true, 512, \JSON_THROW_ON_ERROR);
    }

    private function register(): void
    {
        $options = $this->creationOptions($nonce);
        $this->registration->verifyAndPersist((string) $nonce, $this->authenticator->register($options), 'shop.example', 'My key', 'admin', $this->userId);
    }
}
