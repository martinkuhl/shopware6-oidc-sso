<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialEntity;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Event\PasskeyRegisteredEvent;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminTokenIssuer;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyLimitReachedException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyAuthenticationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRegistrationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingPartyResolver;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PublicError;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Security\UserVerifiedScope;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Subscriber\PasskeyDeletionSubscriber;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\System\User\UserCollection;
use Shopware\Core\System\User\UserEntity;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Administration Passkey self-service registration and usernameless login.
 *
 * - Every ceremony endpoint answers 404 while admin passkeys are disabled in
 *   the plugin settings (H6).
 * - Registering a passkey needs a freshly re-authenticated (`user-verified`)
 *   token — otherwise a hijacked session could plant a permanent way in —
 *   and completes only for the admin who started it (H7, N-M2). The owner
 *   is notified via the PasskeyRegisteredEvent flow trigger.
 * - Login is usernameless: the options never reveal whether an account or
 *   passkey exists (M6). The inactivity modal passes the expected username,
 *   and an assertion by anybody else is refused (F-H6).
 * - The relying party comes from APP_URL, never from the Host header (M17).
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class PasskeyAdminController extends AbstractController
{
    /**
     * @param EntityRepository<UserCollection> $userRepository
     */
    public function __construct(
        private readonly PasskeyRegistrationService $registrationService,
        private readonly PasskeyAuthenticationService $authenticationService,
        private readonly PasskeyCredentialRepository $passkeyCredentialRepository,
        private readonly PasskeyConfig $passkeyConfig,
        private readonly EntityRepository $userRepository,
        private readonly AdminTokenIssuer $tokenIssuer,
        private readonly LoggerInterface $logger,
        private readonly PasskeyDeletionSubscriber $passkeyDeletion,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly PasskeyRelyingPartyResolver $relyingPartyResolver,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly Sw6OidcRateLimiter $rateLimiter,
    ) {
    }

    #[Route(path: '/api/sw6oidc/admin/passkey/registration-options', name: 'api.action.sw6oidc.admin.passkey.registration-options', methods: ['POST'])]
    public function registrationOptions(Request $request, Context $context): JsonResponse
    {
        if (!$this->passkeyConfig->isEnabledForAdmin()) {
            return $this->disabled();
        }

        if (!UserVerifiedScope::isPresent($request)) {
            return new JsonResponse(['error' => 'user_verification_required'], Response::HTTP_FORBIDDEN);
        }

        try {
            $user = $this->currentUser($context);
            $result = $this->registrationService->buildCreationOptions(
                'admin',
                $user->getId(),
                $user->getUsername(),
                trim($user->getFirstName() . ' ' . $user->getLastName()),
                $this->relyingPartyResolver->forAdministration(),
            );
        } catch (PasskeyLimitReachedException) {
            return new JsonResponse(['error' => 'passkey_limit_reached'], Response::HTTP_CONFLICT);
        } catch (AccessDeniedHttpException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            return PublicError::response($this->logger, 'sw6oidc: admin passkey registration could not start.', $exception, 'passkey_unavailable', Response::HTTP_BAD_REQUEST);
        }

        return new JsonResponse(['sessionId' => $result['nonce'], 'options' => json_decode($result['optionsJson'], true)]);
    }

    #[Route(path: '/api/sw6oidc/admin/passkey/registration-verify', name: 'api.action.sw6oidc.admin.passkey.registration-verify', methods: ['POST'])]
    public function registrationVerify(Request $request, Context $context): JsonResponse
    {
        if (!$this->passkeyConfig->isEnabledForAdmin()) {
            return $this->disabled();
        }

        try {
            $user = $this->currentUser($context);
            $nickname = $request->request->get('nickname') !== null ? mb_substr((string) $request->request->get('nickname'), 0, 255) : null;

            $this->registrationService->verifyAndPersist(
                (string) $request->request->get('sessionId'),
                (string) $request->request->get('credential'),
                $request->getHost(),
                $nickname,
                'admin',
                $user->getId(),
            );
        } catch (PasskeyLimitReachedException) {
            return new JsonResponse(['error' => 'passkey_limit_reached'], Response::HTTP_CONFLICT);
        } catch (AccessDeniedHttpException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            return PublicError::response($this->logger, 'sw6oidc: admin passkey registration failed.', $exception, 'passkey_registration_failed', Response::HTTP_BAD_REQUEST);
        }

        $this->eventDispatcher->dispatch(new PasskeyRegisteredEvent(
            'admin',
            $user->getId(),
            $user->getEmail(),
            trim($user->getFirstName() . ' ' . $user->getLastName()),
            $nickname,
            null,
            $context,
        ));

        return new JsonResponse(['status' => true]);
    }

    /**
     * Self-service listing for the "My passkeys" tab on the admin's own
     * profile page — deliberately scoped to the currently authenticated user
     * only (never accepts a userId param). Available even while passkey
     * login is disabled, so existing keys can still be reviewed and removed.
     */
    #[Route(path: '/api/sw6oidc/admin/passkey/my-credentials', name: 'api.action.sw6oidc.admin.passkey.my-credentials', methods: ['GET'])]
    public function myCredentials(Context $context): JsonResponse
    {
        $user = $this->currentUser($context);

        $credentials = $this->passkeyCredentialRepository->findAllForOwner(LoginType::Admin->value, $user->getId(), $context);

        return new JsonResponse([
            'credentials' => array_map(static fn (Sw6OidcPasskeyCredentialEntity $credential): array => [
                'id' => $credential->getId(),
                'nickname' => $credential->getNickname(),
                'createdAt' => $credential->getCreatedAt()?->format(\DATE_ATOM),
                'disabled' => $credential->getDisabledAt() instanceof \DateTimeInterface,
            ], $credentials),
        ]);
    }

    /**
     * Deletes one of the *currently authenticated* admin's own passkeys.
     * Ownership is enforced by PasskeyCredentialRepository::deleteOwnedByUser().
     *
     * If the credential had logged in sessions that are still open, all of
     * the admin's sessions end (R3-M6, PasskeyDeletionSubscriber), this one
     * included, and the response tells the SPA to log itself out.
     */
    #[Route(path: '/api/sw6oidc/admin/passkey/delete', name: 'api.action.sw6oidc.admin.passkey.delete', methods: ['POST'])]
    public function deleteCredential(Request $request, Context $context): JsonResponse
    {
        $user = $this->currentUser($context);
        $id = (string) $request->request->get('id');

        if ($id === '' || !$this->passkeyCredentialRepository->deleteOwnedByUser($id, LoginType::Admin->value, $user->getId(), $context)) {
            return new JsonResponse(['status' => false, 'error' => 'not_found'], 404);
        }

        return new JsonResponse(['status' => true, 'forceLogout' => $this->passkeyDeletion->endedSessionsOf($user->getId())]);
    }

    #[Route(path: '/api/sw6oidc/admin/passkey/login-options', name: 'api.action.sw6oidc.admin.passkey.login-options', defaults: ['auth_required' => false], methods: ['POST'])]
    public function loginOptions(Request $request): JsonResponse
    {
        if (!$this->passkeyConfig->isEnabledForAdmin()) {
            return $this->disabled();
        }

        // Every call stores a ceremony: a consuming budget (N-M15).
        if (!$this->rateLimiter->consume(Sw6OidcRateLimiter::SCOPE_OPTIONS, $request->getClientIp())) {
            return $this->rateLimited();
        }

        try {
            // Always usernameless: listing an account's credentials here would
            // tell anonymous callers which accounts exist (M6).
            $result = $this->authenticationService->buildRequestOptions([], $this->relyingPartyResolver->forAdministration(), PasskeyAuthenticationService::PURPOSE_ADMIN_LOGIN);
        } catch (\Throwable $exception) {
            return PublicError::response($this->logger, 'sw6oidc: admin passkey login could not start.', $exception, 'passkey_unavailable', Response::HTTP_BAD_REQUEST);
        }

        return new JsonResponse(['sessionId' => $result['nonce'], 'options' => json_decode($result['optionsJson'], true)]);
    }

    #[Route(path: '/api/sw6oidc/admin/passkey/login-verify', name: 'api.action.sw6oidc.admin.passkey.login-verify', defaults: ['auth_required' => false], methods: ['POST'])]
    public function loginVerify(Request $request): Response
    {
        if (!$this->passkeyConfig->isEnabledForAdmin()) {
            return $this->disabled();
        }

        if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp())) {
            return $this->rateLimited();
        }

        try {
            $resolved = $this->authenticationService->verifyAssertion(
                (string) $request->request->get('sessionId'),
                (string) $request->request->get('credential'),
                $request->getHost(),
                PasskeyAuthenticationService::PURPOSE_ADMIN_LOGIN,
            );

            if ($resolved['userType'] !== 'admin') {
                throw new \RuntimeException('This passkey is not registered to an Administration user.');
            }

            if (!$this->isExpectedUser($request, $resolved['userId'])) {
                $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp());
                $this->logger->warning('sw6oidc: admin passkey login refused - the passkey belongs to a different account than the session being resumed.');

                // 403, never 401: a 401 on an anonymous call would reach the
                // Administration's token-refresh interceptor and never settle (R3-F5).
                return new JsonResponse(['error' => 'different_user'], Response::HTTP_FORBIDDEN);
            }

            $httpResponse = $this->tokenIssuer->issue($resolved['userId']);
        } catch (\Throwable $exception) {
            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp());

            return PublicError::response($this->logger, 'sw6oidc: admin passkey login failed.', $exception, 'passkey_login_failed', Response::HTTP_BAD_REQUEST);
        }

        $jti = AdminTokenIssuer::accessTokenJti($httpResponse);

        if ($jti !== null) {
            $this->activityRecorder->recordLogin(
                Sw6OidcSession::USER_TYPE_ADMIN,
                $resolved['userId'],
                Sw6OidcSessionActivityDefinition::LOGIN_METHOD_PASSKEY,
                $jti,
                $request,
                passkeyCredentialHash: $resolved['credentialIdHash'],
            );
        }

        return $httpResponse;
    }

    /**
     * Re-login from the inactivity modal must resume the *same* admin's
     * session: when the modal names the expected user, an assertion by any
     * other account is refused.
     */
    private function isExpectedUser(Request $request, string $userId): bool
    {
        $expected = $request->request->get('expectedUsername');

        if (!\is_string($expected) || $expected === '') {
            return true;
        }

        $user = $this->userRepository->search(new Criteria([$userId]), Context::createDefaultContext())->first();

        return $user instanceof UserEntity && $user->getUsername() === $expected;
    }

    private function rateLimited(): JsonResponse
    {
        return new JsonResponse(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
    }

    private function disabled(): JsonResponse
    {
        return new JsonResponse(['error' => 'passkeys_disabled'], Response::HTTP_NOT_FOUND);
    }

    private function currentUser(Context $context): UserEntity
    {
        $source = $context->getSource();

        // Integrations (no user) and other sources get a 403, not a 500 (R3-L16).
        $userId = $source instanceof AdminApiSource ? $source->getUserId() : null;

        if ($userId === null) {
            throw new AccessDeniedHttpException('This action requires an authenticated Administration user.');
        }

        $user = $this->userRepository->search(new Criteria([$userId]), $context)->first();

        if (!$user instanceof UserEntity) {
            throw new \RuntimeException('The authenticated Administration user could not be loaded.');
        }

        return $user;
    }
}
