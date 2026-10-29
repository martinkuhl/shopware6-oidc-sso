<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyCeremonyException;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * The single seam constructing every web-auth/webauthn-lib (5.x) object this
 * plugin needs.
 *
 * - Attestation conveyance is always 'none' (broad authenticator
 *   compatibility over hardware provenance).
 * - User verification (PIN, biometrics) is *required* for registration and
 *   login: a passkey replaces a password, so possession of a key alone is
 *   not enough (H6).
 * - Validators only accept the exact origins pinned into the ceremony, never
 *   subdomains of the RP ID (N-M1).
 * - Offered algorithms: ES256, EdDSA and RS256 — the ones actually verified.
 *
 * 5.x validators no longer take a credential repository: callers look up the
 * CredentialRecord themselves and pass it into check(). All JSON goes through
 * the library's own Symfony serializer.
 */
class WebauthnCeremonyFactory
{
    private ?SerializerInterface $serializer = null;

    public function rpEntity(string $rpId, string $rpName): PublicKeyCredentialRpEntity
    {
        return new PublicKeyCredentialRpEntity($rpName, $rpId);
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    public function credentialParameters(): array
    {
        return [
            new PublicKeyCredentialParameters('public-key', ES256::ID),
            new PublicKeyCredentialParameters('public-key', EdDSA::identifier()),
            new PublicKeyCredentialParameters('public-key', RS256::ID),
        ];
    }

    public function residentKeyAuthenticatorSelection(): AuthenticatorSelectionCriteria
    {
        return new AuthenticatorSelectionCriteria(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        );
    }

    public function serializer(): SerializerInterface
    {
        return $this->serializer ??= (new WebauthnSerializerFactory($this->attestationStatementSupportManager()))->create();
    }

    /**
     * @throws PasskeyCeremonyException
     */
    public function loadCredential(string $json): PublicKeyCredential
    {
        try {
            $credential = $this->serializer()->deserialize($json, PublicKeyCredential::class, 'json');
        } catch (\Throwable $exception) {
            throw new PasskeyCeremonyException('The WebAuthn credential response could not be parsed.', $exception);
        }

        if (!$credential instanceof PublicKeyCredential) {
            throw new PasskeyCeremonyException('The WebAuthn credential response could not be parsed.');
        }

        return $credential;
    }

    /**
     * JSON for navigator.credentials.create()/get() — nulls are skipped, the
     * browser API rejects explicit nulls for several optional members.
     */
    public function serializeOptions(object $options): string
    {
        return $this->serializer()->serialize($options, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]);
    }

    /**
     * @param list<string> $allowedOrigins exact origins the ceremony may come from
     */
    public function attestationResponseValidator(array $allowedOrigins): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create($this->ceremonyStepManagerFactory($allowedOrigins)->creationCeremony());
    }

    /**
     * @param list<string> $allowedOrigins exact origins the ceremony may come from
     */
    public function assertionResponseValidator(array $allowedOrigins): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create($this->ceremonyStepManagerFactory($allowedOrigins)->requestCeremony());
    }

    /**
     * @param list<string> $allowedOrigins
     */
    private function ceremonyStepManagerFactory(array $allowedOrigins): CeremonyStepManagerFactory
    {
        if ($allowedOrigins === []) {
            throw new PasskeyCeremonyException('No allowed origin is configured for this passkey ceremony.');
        }

        $factory = new CeremonyStepManagerFactory();
        $factory->setAlgorithmManager($this->coseAlgorithmManager());
        $factory->setAttestationStatementSupportManager($this->attestationStatementSupportManager());
        $factory->setAllowedOrigins($allowedOrigins, false);

        return $factory;
    }

    private function attestationStatementSupportManager(): AttestationStatementSupportManager
    {
        return new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]);
    }

    private function coseAlgorithmManager(): CoseAlgorithmManager
    {
        return CoseAlgorithmManager::create()->add(ES256::create(), new EdDSA(), RS256::create());
    }
}
