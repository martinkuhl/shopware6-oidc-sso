<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialEntity;
use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyCeremonyException;
use Psr\Log\LoggerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Builds WebAuthn authentication (assertion) ceremonies and verifies the
 * result, resolving back to our own userType/userId. Used for usernameless
 * (discoverable, empty allowCredentials) login on both sides, and for the
 * Administration step-up (allowCredentials = the current admin's own keys).
 *
 * The relying party (RP ID and exact allowed origins) is pinned into the
 * ceremony when the options are built; verification never trusts the
 * request's host. User verification is always required.
 */
class PasskeyAuthenticationService
{
    private const TTL_SECONDS = 300;
    private const CACHE_PREFIX = 'sw6oidc_passkey_auth_';

    /**
     * Ceremony purposes (R3-M7): a ceremony can only be redeemed by the
     * endpoint it was started for — a Storefront ceremony never logs into the
     * Administration, even with an RP ID that covers both hosts, and a
     * step-up ceremony belongs to the admin who started it.
     */
    public const PURPOSE_ADMIN_LOGIN = 'admin-login';

    public static function storefrontLoginPurpose(string $salesChannelId): string
    {
        return 'storefront-login:' . $salesChannelId;
    }

    public static function adminStepUpPurpose(string $userId): string
    {
        return 'admin-stepup:' . $userId;
    }

    public function __construct(
        private readonly WebauthnCeremonyFactory $ceremonyFactory,
        private readonly PasskeyCredentialRepository $credentialRepository,
        private readonly AtomicCacheInterface $cache,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials empty = usernameless/discoverable login
     * @param string                          $purpose          see PURPOSE_ADMIN_LOGIN and the *Purpose() factories
     *
     * @return array{optionsJson: string, nonce: string}
     */
    public function buildRequestOptions(array $allowCredentials, PasskeyRelyingParty $relyingParty, string $purpose): array
    {
        $challenge = random_bytes(32);
        $options = $this->buildOptions($challenge, $relyingParty->id, $allowCredentials);

        $nonce = bin2hex(random_bytes(16));

        // Raw inputs, not the serialized options — rebuilt via the
        // constructor on verify (same approach as PasskeyRegistrationService).
        $this->cache->save(
            self::CACHE_PREFIX . $nonce,
            json_encode([
                'purpose' => $purpose,
                'challenge' => bin2hex($challenge),
                'rpId' => $relyingParty->id,
                'origins' => $relyingParty->origins,
                'allowCredentials' => array_map(
                    static fn (PublicKeyCredentialDescriptor $descriptor): array => [
                        'type' => $descriptor->type,
                        'id' => bin2hex($descriptor->id),
                        'transports' => $descriptor->transports,
                    ],
                    $allowCredentials,
                ),
            ], JSON_THROW_ON_ERROR),
            self::TTL_SECONDS,
        );

        return ['optionsJson' => $this->ceremonyFactory->serializeOptions($options), 'nonce' => $nonce];
    }

    /**
     * @param string $host the request host (passed to the library; the origin check itself uses the pinned origins)
     *
     * @param string $expectedPurpose the purpose the ceremony must have been started for (R3-M7)
     *
     * @return array{userType: string, userId: string, credentialId: string, credentialIdHash: string}
     *
     * @throws PasskeyCeremonyException
     */
    public function verifyAssertion(string $nonce, string $assertionResponseJson, string $host, string $expectedPurpose): array
    {
        $raw = $this->cache->getAndDelete(self::CACHE_PREFIX . $nonce);

        if ($raw === null) {
            throw new PasskeyCeremonyException('Unknown, expired, or already-used passkey login ceremony.');
        }

        $stored = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

        if (!\is_array($stored) || ($stored['purpose'] ?? null) !== $expectedPurpose) {
            throw new PasskeyCeremonyException('The passkey ceremony was started for a different purpose.');
        }

        $options = $this->buildOptions(
            (string) hex2bin($stored['challenge']),
            $stored['rpId'],
            array_map(
                static fn (array $descriptor): PublicKeyCredentialDescriptor => new PublicKeyCredentialDescriptor(
                    $descriptor['type'],
                    (string) hex2bin($descriptor['id']),
                    $descriptor['transports'],
                ),
                $stored['allowCredentials'],
            ),
        );

        $publicKeyCredential = $this->ceremonyFactory->loadCredential($assertionResponseJson);
        $response = $publicKeyCredential->response;

        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new PasskeyCeremonyException('Expected a WebAuthn assertion (login) response.');
        }

        $rawId = $publicKeyCredential->rawId;
        $entity = $this->credentialRepository->findEntityByCredentialId(base64_encode($rawId));

        if (!$entity instanceof Sw6OidcPasskeyCredentialEntity) {
            throw new PasskeyCeremonyException('This passkey is not registered.');
        }

        if ($entity->getDisabledAt() instanceof \DateTimeInterface) {
            throw new PasskeyCeremonyException('This passkey has been disabled.');
        }

        $record = $this->credentialRepository->toRecord($entity);

        try {
            $record = $this->ceremonyFactory->assertionResponseValidator(array_values($stored['origins'] ?? []))->check(
                $record,
                $response,
                $options,
                $host,
                // A ceremony scoped to known credentials (step-up) identified
                // the user beforehand, so the authenticator's userHandle is
                // optional; usernameless login must get it from the response.
                $options->allowCredentials !== [] ? $record->userHandle : null,
            );
        } catch (CounterException $exception) {
            $this->credentialRepository->disable(base64_encode($rawId));
            $this->logger?->warning('sw6oidc: passkey signature counter did not increase — possible cloned authenticator; the credential was disabled.', [
                'credentialId' => $entity->getId(),
                'userType' => $entity->getUserType(),
                'userId' => $entity->getUserId(),
            ]);

            throw new PasskeyCeremonyException('This passkey has been disabled.', $exception);
        } catch (\Throwable $exception) {
            throw new PasskeyCeremonyException($exception->getMessage(), $exception);
        }

        $this->credentialRepository->updateAfterAssertion($entity, $record);

        return [
            'userType' => $entity->getUserType(),
            'userId' => $entity->getUserId(),
            'credentialId' => $entity->getId(),
            'credentialIdHash' => (string) $entity->getCredentialIdHash(),
        ];
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     */
    private function buildOptions(string $challenge, string $rpId, array $allowCredentials): PublicKeyCredentialRequestOptions
    {
        return new PublicKeyCredentialRequestOptions(
            $challenge,
            rpId: $rpId,
            allowCredentials: $allowCredentials,
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: 60000,
        );
    }
}
