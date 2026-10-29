<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthorizationRequestBuilder;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthTimeValidator;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyCeremonyException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyAuthenticationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingPartyResolver;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * The one "fresh authentication" primitive for the Administration: proves
 * that the person at the keyboard is the logged-in admin *right now*, before
 * anything that core protects with password re-confirmation (`user-verified`
 * tokens), or that would give a hijacked session a permanent way in
 * ("Connect SSO", new passkeys).
 *
 * Two ways to prove it:
 *  - OIDC: a round trip to the admin's own bound provider with
 *    `prompt=login`; the id_token's `auth_time` must be after the
 *    round trip started and the subject must be the admin's binding.
 *  - Passkey: an assertion with one of the admin's own passkeys, with user
 *    verification (PIN/biometrics) required.
 *
 * Either way the result is a short-lived access token with the
 * `user-verified` scope and no refresh token (AdminOidcGrant step-up mode),
 * the same shape core's password re-confirmation produces.
 */
class StepUpService
{
    private const NONCE_TTL_SECONDS = 120;
    private const NONCE_PREFIX = 'sw6oidc_step_up_';

    public function __construct(
        private readonly UserProviderBindingService $bindingService,
        private readonly ProviderResolver $providerResolver,
        private readonly AuthorizationRequestBuilder $requestBuilder,
        private readonly AtomicCacheInterface $cache,
        private readonly PasskeyAuthenticationService $passkeyAuthenticationService,
        private readonly PasskeyCredentialRepository $passkeyCredentialRepository,
        private readonly PasskeyRelyingPartyResolver $relyingPartyResolver,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * The authorize URL of an OIDC re-authentication at the admin's bound
     * provider, or null when the admin has no (active) binding.
     */
    public function oidcAuthorizeUrl(string $userId, string $redirectUri, Context $context): ?string
    {
        $provider = $this->boundProvider($userId, $context);

        if (!$provider instanceof \MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity) {
            return null;
        }

        return $this->requestBuilder->build(
            $provider,
            'admin',
            '',
            $redirectUri,
            AuthorizationFlowContext::PURPOSE_STEP_UP,
            $userId,
            ['prompt' => 'login'],
        );
    }

    /**
     * Checks the OIDC re-authentication and returns a one-time step-up nonce
     * for the admin who started it.
     *
     * @throws InvalidStateException when the login isn't fresh or isn't the admin's own identity
     */
    public function completeOidc(OidcCallbackResult $result, Context $context): string
    {
        $userId = $result->flow->expectedUserId;
        \assert($userId !== null);

        AuthTimeValidator::assertFresh($result);

        $identity = $result->identity();
        $owner = $this->bindingService->findUserIdBySubject(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $identity, $context);

        if ($owner !== $userId) {
            throw new InvalidStateException('The re-authentication was performed with a different identity.');
        }

        $nonce = bin2hex(random_bytes(32));
        $this->cache->save(self::NONCE_PREFIX . $nonce, $userId, self::NONCE_TTL_SECONDS);

        return $nonce;
    }

    /**
     * Redeems a step-up nonce; true only for the admin it was issued to.
     */
    public function redeemNonce(string $nonce, string $userId): bool
    {
        if ($nonce === '') {
            return false;
        }

        return $this->cache->getAndDelete(self::NONCE_PREFIX . $nonce) === $userId;
    }

    public function hasOidc(string $userId, Context $context): bool
    {
        return $this->boundProvider($userId, $context) instanceof \MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
    }

    public function hasPasskey(string $userId): bool
    {
        return $this->passkeyDescriptors($userId) !== [];
    }

    /**
     * @return array{optionsJson: string, nonce: string}|null null when the admin has no usable passkey
     */
    public function passkeyOptions(string $userId): ?array
    {
        $descriptors = $this->passkeyDescriptors($userId);

        if ($descriptors === []) {
            return null;
        }

        return $this->passkeyAuthenticationService->buildRequestOptions(
            $descriptors,
            $this->relyingPartyResolver->forAdministration(),
            PasskeyAuthenticationService::adminStepUpPurpose($userId),
        );
    }

    /**
     * @throws PasskeyCeremonyException when the assertion fails or belongs to another account
     */
    public function verifyPasskey(string $ceremonyId, string $credentialJson, string $host, string $userId): void
    {
        $resolved = $this->passkeyAuthenticationService->verifyAssertion($ceremonyId, $credentialJson, $host, PasskeyAuthenticationService::adminStepUpPurpose($userId));

        if ($resolved['userType'] !== Sw6OidcUserProviderEntity::USER_TYPE_ADMIN || $resolved['userId'] !== $userId) {
            $this->logger->warning('sw6oidc: step-up refused, the passkey belongs to a different account.', ['userId' => $userId]);

            throw new PasskeyCeremonyException('This passkey belongs to a different account.');
        }
    }

    private function boundProvider(string $userId, Context $context): ?Sw6OidcProviderEntity
    {
        $providerId = $this->bindingService->getBoundProviderId(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $userId, $context);

        if ($providerId === null) {
            return null;
        }

        try {
            return $this->providerResolver->getActiveById($providerId, LoginType::Admin->value, $context);
        } catch (ProviderNotFoundException) {
            return null;
        }
    }

    /**
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function passkeyDescriptors(string $userId): array
    {
        $userHandle = hash('sha256', Sw6OidcUserProviderEntity::USER_TYPE_ADMIN . ':' . $userId, true);

        return array_values(array_map(
            static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
            $this->passkeyCredentialRepository->findAllForUserHandle($userHandle, false),
        ));
    }
}
