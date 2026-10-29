<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AccountSsoLinkedEvent;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginErrorTicketStore;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginNonce;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginNonceService;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminTokenIssuer;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\StepUpService;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthorizationRequestBuilder;
use MartinKuhl\Sw6Oidc\Service\Oidc\LogoutContext;
use MartinKuhl\Sw6Oidc\Service\Oidc\LogoutContextStore;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackProcessor;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use MartinKuhl\Sw6Oidc\Service\Oidc\RpInitiatedLogoutService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AdminProvisioningService;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AdminProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\IdentityResolver;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\UnknownStateException;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use MartinKuhl\Sw6Oidc\Service\Security\PublicError;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Security\UserVerifiedScope;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\PlatformRequest;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * The Administration OIDC bridge: SP-initiated login, IdP callback, and the
 * nonce-exchange endpoint the `sw-login` override calls to obtain a real
 * Shopware admin access token. Three legs instead of one, because the
 * Administration is an SPA: the IdP redirect lands on a server route, which
 * hands a one-time, browser-bound nonce to the SPA, which exchanges it for
 * a token over XHR (see CLAUDE.md, "Admin OIDC ↔ League OAuth2 bridge").
 */
#[Route(defaults: ['_routeScope' => ['api'], 'auth_required' => false])]
class OidcAdminAuthController extends AbstractController
{
    /** Token-response field / logout parameter carrying the admin's login-session handle. */
    public const LOGIN_SESSION_FIELD = 'sw6oidc_login_session';

    /** Round-trip id of an SSO re-login started from the inactivity modal. */
    public const RETURN_ID_PARAMETER = 'sw6oidc_return';

    /** How long an admin OIDC login may take from IdP callback to nonce exchange. */
    private const PENDING_SESSION_TTL_SECONDS = 600;

    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly AuthorizationRequestBuilder $requestBuilder,
        private readonly OidcCallbackProcessor $callbackProcessor,
        private readonly AdminProvisioningService $adminProvisioningService,
        private readonly AdminLoginNonceService $loginNonceService,
        private readonly AdminTokenIssuer $tokenIssuer,
        private readonly string $administrationBaseUrl,
        private readonly LoggerInterface $logger,
        private readonly PasskeyConfig $passkeyConfig,
        private readonly PasskeyCredentialRepository $passkeyCredentialRepository,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
        private readonly LogoutContextStore $logoutContextStore,
        private readonly RpInitiatedLogoutService $rpInitiatedLogoutService,
        private readonly AdminLoginErrorTicketStore $loginErrorTicketStore,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcRateLimiter $rateLimiter,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly IdentityResolver $identityResolver,
        private readonly StepUpService $stepUpService,
        private readonly Connection $connection,
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    /**
     * Redeems the one-time error ticket the callback attached to an
     * access-control denial (see AdminLoginErrorTicketStore). Anonymous by
     * necessity (pre-auth screen); the ticket itself is the capability.
     */
    #[Route(
        path: '/api/sw6oidc/admin/login-error/{ticket}',
        name: 'api.action.sw6oidc.admin.login-error',
        methods: ['GET'],
    )]
    public function loginError(string $ticket, Request $request): JsonResponse
    {
        if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp())) {
            return new JsonResponse(['message' => null], Response::HTTP_TOO_MANY_REQUESTS);
        }

        $message = $this->loginErrorTicketStore->redeem($ticket);

        if ($message === null) {
            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp());
        }

        return new JsonResponse(['message' => $message]);
    }

    /**
     * Called by the `sw-login` override on mount so it only shows the "Login
     * with SSO"/"Login with Passkey" buttons when something is actually
     * configured — this endpoint is anonymous (it runs before any user is
     * known), so "available" here only ever means "at least one active
     * admin-scoped provider exists" / "passkey login is enabled AND at least
     * one admin has actually registered one", never anything about which
     * passkey a not-yet-identified visitor specifically holds. The passkey
     * enabled-toggle alone isn't enough - a freshly-enabled instance with
     * zero registered admin passkeys would otherwise show a button that's
     * guaranteed to fail for literally everyone until someone registers one.
     */
    #[Route(
        path: '/api/sw6oidc/admin/login-options',
        name: 'api.action.sw6oidc.admin.login-options',
        methods: ['GET'],
    )]
    public function loginOptions(): JsonResponse
    {
        $context = Context::createDefaultContext();

        return new JsonResponse([
            // One entry per visible admin-scoped provider, ordered by
            // sortOrder - `label` is null (rather than a hardcoded generic
            // string) when the provider has no displayName, so the JS side
            // can fall back to its own translated "Login with SSO" text.
            'ssoProviders' => array_map(
                static fn (Sw6OidcProviderEntity $provider): array => [
                    'id' => $provider->getId(),
                    'label' => $provider->getDisplayName(),
                ],
                $this->providerResolver->getVisibleProviders(LoginType::Admin->value, $context),
            ),
            'passkeyAvailable' => $this->passkeyConfig->isEnabledForAdmin()
                && $this->passkeyCredentialRepository->existsForUserType(LoginType::Admin->value, $context),
            'passwordLoginDisabled' => $this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Admin->value, $context),
        ]);
    }

    #[Route(
        path: '/api/sw6oidc/admin/login',
        name: 'api.action.sw6oidc.admin.login',
        methods: ['GET'],
    )]
    public function login(Request $request): RedirectResponse
    {
        // Every flow start stores a flow context: a consuming budget (N-M15).
        if (!$this->rateLimiter->consume(Sw6OidcRateLimiter::SCOPE_FLOW_START, $request->getClientIp())) {
            $this->logger->warning('sw6oidc: admin SSO flow start rate-limited.');

            return new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'oidc_failed']));
        }

        $context = Context::createDefaultContext();
        $providerId = $request->query->get('providerId');

        try {
            $provider = $providerId !== null
                ? $this->providerResolver->getActiveById((string) $providerId, LoginType::Admin->value, $context)
                : $this->providerResolver->resolveDefault(LoginType::Admin->value, $context);
        } catch (ProviderNotFoundException $exception) {
            $this->logger->warning('sw6oidc: admin SSO login requested but no active provider is configured.', [
                'exception' => $exception->getMessage(),
            ]);

            return new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'provider_unavailable']));
        }

        $redirectUri = $this->generateUrl('api.action.sw6oidc.admin.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
        // The inactivity modal's round-trip id (service/sso-return-route.js),
        // echoed back after the callback; nothing else is carried.
        $returnId = (string) $request->query->get(self::RETURN_ID_PARAMETER);
        $relayState = preg_match('/^[a-f0-9]{32}$/', $returnId) === 1 ? $returnId : '';

        return new RedirectResponse($this->requestBuilder->build($provider, LoginType::Admin->value, $relayState, $redirectUri));
    }

    #[Route(
        path: '/api/sw6oidc/admin/callback',
        name: 'api.action.sw6oidc.admin.callback',
        methods: ['GET'],
    )]
    public function callback(Request $request): Response
    {
        $context = Context::createDefaultContext();

        if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_CALLBACK_ADMIN, $request->getClientIp())) {
            $this->logger->warning('sw6oidc: admin OIDC callback rate-limited.');

            return new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'oidc_failed']));
        }

        if ($request->query->get('error') !== null) {
            $flow = $this->callbackProcessor->abortFlowWithIdpError($request->query->get('state'), Sw6OidcUserProviderEntity::USER_TYPE_ADMIN);

            if (!$flow instanceof AuthorizationFlowContext) {
                // No flow of this browser: possibly forged, so it counts (R4-L4).
                $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_CALLBACK_ADMIN, $request->getClientIp());
            }

            $this->logger->notice(
                'sw6oidc: IdP returned an OAuth error on the admin callback.',
                OidcCallbackProcessor::idpErrorLogContext($request->query->get('error'), $request->query->get('error_description'))
                + ['knownFlow' => $flow instanceof AuthorizationFlowContext],
            );

            // A step-up popup must report back to its opener, never land on the login page (R3-F9).
            return $flow?->purpose === AuthorizationFlowContext::PURPOSE_STEP_UP
                ? $this->stepUpResultPage(['type' => 'sw6oidc-step-up', 'error' => 'step_up_failed'])
                : new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'oidc_failed']));
        }

        $redirectUri = $this->generateUrl('api.action.sw6oidc.admin.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);

        $flow = null;

        try {
            $flow = $this->callbackProcessor->consumeFlow($request->query->get('state'), Sw6OidcUserProviderEntity::USER_TYPE_ADMIN);
            $result = $this->callbackProcessor->processFlow($flow, $request->query->get('code'), $redirectUri, $context);

            if ($result->flow->purpose === AuthorizationFlowContext::PURPOSE_LINK) {
                return $this->completeLink($result, $context);
            }

            if ($result->flow->purpose === AuthorizationFlowContext::PURPOSE_STEP_UP) {
                return $this->completeStepUp($result, $context);
            }

            if ($result->flow->purpose !== AuthorizationFlowContext::PURPOSE_LOGIN) {
                throw new InvalidStateException(sprintf('Unsupported flow purpose "%s" on the admin callback.', $result->flow->purpose));
            }

            $adminUser = $this->adminProvisioningService->findOrCreateAdmin($result->provider, $result->profile, $result->identity(), $context);


            $this->logoutContextStore->rememberForAdmin($adminUser->getId(), $result->provider->getId());

            // Registered now (the id_token and IdP tokens are only known here),
            // completed with the access token's jti once the SPA redeems the
            // nonce; an unredeemed entry expires with the nonce window.
            $pendingSession = $this->sessionRegistry->register(
                $result->provider->getId(),
                $result->identity()->subject,
                $result->sessionId(),
                Sw6OidcSession::USER_TYPE_ADMIN,
                $adminUser->getId(),
                'pending:' . bin2hex(random_bytes(16)),
                null,
                $result->idToken(),
                $result->idpAccessToken(),
                $result->idpRefreshToken(),
                self::PENDING_SESSION_TTL_SECONDS,
            );

            $nonce = $this->loginNonceService->createNonce($adminUser->getId(), $result->provider->getId(), $pendingSession->id, $result->flow->browserBinding);
            $this->logger->debug('sw6oidc: admin OIDC callback succeeded, redirecting back into the Administration SPA.', [
                'userId' => $adminUser->getId(),
            ]);

            $query = ['sw6oidc_nonce' => $nonce];

            if (preg_match('/^[a-f0-9]{32}$/', $result->flow->relayState) === 1) {
                $query[self::RETURN_ID_PARAMETER] = $result->flow->relayState;
            }

            return new RedirectResponse($this->administrationLoginUrl($query));
        } catch (AccessControlDeniedException $exception) {
            if ($flow->purpose === AuthorizationFlowContext::PURPOSE_STEP_UP) {
                return $this->stepUpResultPage(['type' => 'sw6oidc-step-up', 'error' => 'step_up_failed']);
            }

            $query = ['sw6oidc_error' => 'access_denied'];
            $message = $exception->getDisplayMessage();

            if ($message !== null) {
                $query['sw6oidc_error_ticket'] = $this->loginErrorTicketStore->create($message);
            }

            return new RedirectResponse($this->administrationLoginUrl($query));
        } catch (AccountLinkingRequiredException | EmailNotVerifiedException | ProviderMismatchException | SubjectAlreadyLinkedException $exception) {
            if ($flow->purpose === AuthorizationFlowContext::PURPOSE_STEP_UP) {
                return $this->stepUpResultPage(['type' => 'sw6oidc-step-up', 'error' => 'step_up_failed']);
            }

            $this->logger->notice('sw6oidc: admin OIDC login refused by the account policy.', [
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
            ]);

            return new RedirectResponse($this->administrationLoginUrl([
                'sw6oidc_error' => match (true) {
                    $exception instanceof AccountLinkingRequiredException => 'link_required',
                    $exception instanceof EmailNotVerifiedException => 'email_not_verified',
                    default => 'provider_mismatch',
                },
            ]));
        } catch (AdminProvisioningDeniedException $exception) {
            $this->logger->warning('sw6oidc: admin OIDC callback failed.', [
                'exception' => $exception->getMessage(),
                'reason' => $exception->reason,
                'providerId' => $result->provider->getId(),
            ]);

            return new RedirectResponse($this->administrationLoginUrl([
                'sw6oidc_error' => match ($exception->reason) {
                    AdminProvisioningDeniedException::REASON_NO_ROLE => 'admin_role_missing',
                    AdminProvisioningDeniedException::REASON_AUTO_CREATE_DISABLED => 'admin_auto_create_disabled',
                    // Inactive or missing: the generic message, nothing about the account.
                    default => 'oidc_failed',
                },
            ]));
        } catch (UnknownStateException $exception) {
            // Expired/reused state or junk: not counted (N-M3).
            $this->logger->notice('sw6oidc: admin OIDC callback with an unknown state.', ['exception' => $exception->getMessage()]);

            return new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'oidc_failed']));
        } catch (\Throwable $exception) {
            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_CALLBACK_ADMIN, $request->getClientIp());
            $this->logger->warning('sw6oidc: admin OIDC callback failed.', [
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
                // Often the actually-useful detail: e.g. a DB/DBAL exception
                // wraps the driver's own message (missing column, FK
                // violation, ...) as the previous exception rather than in
                // its own getMessage().
                'previousException' => $exception->getPrevious()?->getMessage(),
                'purpose' => $flow?->purpose,
            ]);

            if ($flow?->purpose === AuthorizationFlowContext::PURPOSE_STEP_UP) {
                // The popup reports the failure to its opener (R3-F9).
                return $this->stepUpResultPage(['type' => 'sw6oidc-step-up', 'error' => 'step_up_failed']);
            }

            return new RedirectResponse($this->administrationLoginUrl(['sw6oidc_error' => 'oidc_failed']));
        }
    }

    /**
     * Starts "Connect SSO" for the logged-in admin: returns the IdP authorize
     * URL of an OIDC round trip whose callback binds the IdP identity to
     * exactly this user. Requires a freshly re-authenticated (`user-verified`)
     * token — otherwise a hijacked session could attach the attacker's own
     * IdP account as a permanent way in.
     */
    #[Route(
        path: '/api/sw6oidc/admin/link/start',
        name: 'api.action.sw6oidc.admin.link-start',
        defaults: ['auth_required' => true],
        methods: ['POST'],
    )]
    public function startLink(Request $request, Context $context): JsonResponse
    {
        $source = $context->getSource();

        if (!$source instanceof AdminApiSource || $source->getUserId() === null) {
            return $this->json(['error' => 'unauthorized'], Response::HTTP_FORBIDDEN);
        }

        if (!UserVerifiedScope::isPresent($request)) {
            return $this->json(['error' => 'user_verification_required'], Response::HTTP_FORBIDDEN);
        }

        // Every start stores a flow: a consuming budget per admin (R3-L41).
        if (!$this->rateLimiter->consume(Sw6OidcRateLimiter::SCOPE_FLOW_START . ':' . $source->getUserId(), $request->getClientIp())) {
            return $this->json(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }

        try {
            $provider = $this->providerResolver->getActiveById((string) $request->request->get('providerId'), LoginType::Admin->value, $context);
        } catch (ProviderNotFoundException) {
            return $this->json(['error' => 'provider_unavailable'], Response::HTTP_NOT_FOUND);
        }

        $redirectUri = $this->generateUrl('api.action.sw6oidc.admin.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);

        return $this->json(['authorizeUrl' => $this->requestBuilder->build(
            $provider,
            'admin',
            '',
            $redirectUri,
            AuthorizationFlowContext::PURPOSE_LINK,
            $source->getUserId(),
        )]);
    }

    /**
     * Called by the `sw-login` Administration override via XHR once it spots
     * `?sw6oidc_nonce=` in its own URL. Redeems the nonce, marks the live
     * request with the resolved admin user id, and runs it through the exact
     * same in-process AuthorizationServer bridge Shopware's own password grant
     * uses — the JSON body returned here *is* a normal OAuth2 token response.
     */
    #[Route(
        path: '/api/sw6oidc/admin/token',
        name: 'api.action.sw6oidc.admin.token',
        methods: ['POST'],
    )]
    public function exchangeNonce(Request $request): Response
    {
        if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp())) {
            return $this->json(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }

        $nonce = $request->request->get('sw6oidc_nonce');
        $loginNonce = $this->loginNonceService->redeemNonce(\is_string($nonce) ? $nonce : null);

        if (!$loginNonce instanceof AdminLoginNonce) {
            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_REDEEM, $request->getClientIp());

            // Was silent before - a redirect back from the IdP that looks
            // clean in the logs above (provisioning succeeded, nonce
            // minted, redirect issued) can still end here if the SPA calls
            // this twice (nonces are single-use) or the redirect round-trip
            // took long enough for the 120s TTL to lapse.
            $this->logger->warning('sw6oidc: admin token exchange rejected - unknown, expired, or already-used nonce.', [
                'hasNonce' => \is_string($nonce) && $nonce !== '',
            ]);

            return $this->json(['error' => 'invalid_grant', 'error_description' => 'Unknown, expired, or already-used login nonce.'], 400);
        }

        $userId = $loginNonce->userId;

        $this->logger->debug('sw6oidc: admin login nonce redeemed, exchanging for an access token.', [
            'userId' => $userId,
        ]);

        try {
            $response = $this->tokenIssuer->issue($userId);
        } catch (\Throwable $exception) {
            return PublicError::response($this->logger, 'sw6oidc: admin token exchange failed.', $exception, 'invalid_grant', Response::HTTP_BAD_REQUEST, ['userId' => $userId]);
        }

        $this->logger->debug('sw6oidc: admin token exchange succeeded.', ['userId' => $userId]);

        $jti = $this->accessTokenJti($response);
        $registrySession = null;

        if ($jti !== null && $loginNonce->registrySessionId !== null) {
            $this->sessionRegistry->activate($loginNonce->registrySessionId, $jti);
            $registrySession = $this->sessionRegistry->get($loginNonce->registrySessionId);

            // The Administration's handle on exactly this login session: sent
            // back at logout, it survives token refreshes (unlike the jti).
            if ($registrySession instanceof Sw6OidcSession) {
                $response = $this->withLoginSessionId($response, $registrySession->id);
            }
        }

        if ($jti !== null) {
            $this->activityRecorder->recordLogin(
                Sw6OidcSession::USER_TYPE_ADMIN,
                $userId,
                Sw6OidcSessionActivityDefinition::LOGIN_METHOD_OIDC,
                $jti,
                $request,
                $loginNonce->providerId,
                $registrySession,
            );
        }

        return $response;
    }

    /**
     * RP-Initiated Logout for Administration users. Called by the
     * `sw-admin-menu` override right before its normal local logout; returns
     * the IdP logout URL the SPA should navigate to, or `null` (plain local
     * logout) when this admin didn't log in via OIDC, the provider is gone,
     * or it has no end_session_endpoint. Never fails the logout itself.
     */
    #[Route(
        path: '/api/sw6oidc/admin/logout',
        name: 'api.action.sw6oidc.admin.logout',
        defaults: ['auth_required' => true],
        methods: ['POST'],
    )]
    public function logout(Request $request, Context $context): JsonResponse
    {
        $source = $context->getSource();
        $userId = $source instanceof AdminApiSource ? $source->getUserId() : null;

        $logoutContext = null;

        if ($userId !== null) {
            [$logoutContext, $endedRegistrySessionId] = $this->consumeAdminLogoutContext($userId, $request);

            $currentJti = $request->attributes->get(PlatformRequest::ATTRIBUTE_OAUTH_ACCESS_TOKEN_ID);
            $this->activityRecorder->recordLogout(
                Sw6OidcSession::USER_TYPE_ADMIN,
                $userId,
                Sw6OidcSessionActivityDefinition::LOGOUT_REASON_LOGOUT,
                \is_string($currentJti) ? $currentJti : null,
                $endedRegistrySessionId,
            );
        }

        if (!$logoutContext instanceof LogoutContext) {
            $this->logger->debug('sw6oidc: no OIDC logout context for this admin session, skipping RP-initiated logout.', [
                'userId' => $userId,
            ]);

            return new JsonResponse(['logoutUrl' => null]);
        }

        try {
            $provider = $this->providerResolver->getActiveById($logoutContext->providerId, LoginType::Admin->value, $context);
        } catch (ProviderNotFoundException $exception) {
            $this->logger->warning('sw6oidc: admin RP-initiated logout skipped, provider no longer active.', [
                'providerId' => $logoutContext->providerId,
                'exception' => $exception->getMessage(),
            ]);

            return new JsonResponse(['logoutUrl' => null]);
        }

        $this->rpInitiatedLogoutService->revokeTokens($provider, $logoutContext);

        $logoutUrl = $this->rpInitiatedLogoutService->buildLogoutUrl(
            $provider,
            $logoutContext->idToken,
            rtrim($this->administrationBaseUrl, '/') . '/',
            PostLogoutState::TARGET_ADMIN,
        );

        $this->logger->debug('sw6oidc: resolved admin RP-initiated logout URL.', [
            'userId' => $userId,
            'providerId' => $logoutContext->providerId,
            'hasLogoutUrl' => $logoutUrl !== null,
        ]);

        return new JsonResponse(['logoutUrl' => $logoutUrl]);
    }

    /**
     * Finds exactly the login session being logged out: by the login-session
     * handle the Administration received with its token response (survives
     * refreshes), else by the current access token's jti (first minutes of a
     * login). Only an exact match is removed from the registry — guessing
     * "the newest session" would end another device's registry entry and
     * send that device's id_token as the hint (N-M4). Without a match, the
     * provider of the admin's last login still yields an IdP logout URL.
     *
     * @return array{0: LogoutContext|null, 1: string|null} the context and the ended registry entry id
     */
    private function consumeAdminLogoutContext(string $userId, Request $request): array
    {
        $loginSessionId = $request->request->get(self::LOGIN_SESSION_FIELD);
        $currentJti = $request->attributes->get(PlatformRequest::ATTRIBUTE_OAUTH_ACCESS_TOKEN_ID);

        $session = \is_string($loginSessionId) && $loginSessionId !== ''
            ? $this->sessionRegistry->findForUser(Sw6OidcSession::USER_TYPE_ADMIN, $userId, $loginSessionId)
            : null;

        if (!$session instanceof Sw6OidcSession && \is_string($currentJti) && $currentJti !== '') {
            $session = $this->sessionRegistry->findBySessionKey(Sw6OidcSession::USER_TYPE_ADMIN, $userId, $currentJti);
        }

        if (!$session instanceof Sw6OidcSession) {
            return [$this->logoutContextStore->consumeForAdmin($userId), null];
        }

        $this->sessionRegistry->remove($session);

        return [
            new LogoutContext($session->providerId, $session->idToken, $session->idpAccessToken, $session->idpRefreshToken),
            $session->id,
        ];
    }

    /**
     * Adds the login-session handle to the OAuth token response JSON.
     */
    private function withLoginSessionId(Response $response, string $loginSessionId): Response
    {
        $payload = json_decode((string) $response->getContent(), true);

        if (!\is_array($payload)) {
            return $response;
        }

        $payload[self::LOGIN_SESSION_FIELD] = $loginSessionId;
        $response->setContent(json_encode($payload, JSON_THROW_ON_ERROR));

        return $response;
    }

    private function accessTokenJti(Response $tokenResponse): ?string
    {
        $jti = AdminTokenIssuer::accessTokenJti($tokenResponse);

        if ($jti === null) {
            $this->logger->warning('sw6oidc: admin token response had no readable jti, session not registered.');
        }

        return $jti;
    }

    /**
     * @param array<string, string> $query
     */
    private function administrationLoginUrl(array $query): string
    {
        return rtrim($this->administrationBaseUrl, '/') . '/#/login?' . http_build_query($query);
    }

    /**
     * OIDC step-up round trip, run in a popup the Administration opened: hands
     * the one-time step-up nonce (or the failure) back to the opener via
     * postMessage, restricted to the Administration's own origin, and closes.
     */
    private function completeStepUp(OidcCallbackResult $result, Context $context): Response
    {
        try {
            $message = ['type' => 'sw6oidc-step-up', 'nonce' => $this->stepUpService->completeOidc($result, $context)];
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: OIDC step-up refused.', [
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
                'userId' => $result->flow->expectedUserId,
            ]);
            $message = ['type' => 'sw6oidc-step-up', 'error' => 'step_up_failed'];
        }

        return $this->stepUpResultPage($message);
    }

    /**
     * The step-up popup's last page: posts the message to the Administration
     * (its own origin only) and closes.
     *
     * @param array{type: string, nonce?: string, error?: string} $message
     */
    private function stepUpResultPage(array $message): Response
    {
        $parts = parse_url($this->administrationBaseUrl);
        $origin = ($parts['scheme'] ?? 'https') . '://' . ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $scriptNonce = base64_encode(random_bytes(16));
        $payload = json_encode($message, JSON_THROW_ON_ERROR | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $targetOrigin = json_encode($origin, JSON_THROW_ON_ERROR | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        $response = new Response(
            '<!doctype html><html><head><meta charset="utf-8"><title>Single sign-on</title></head><body>'
            . '<script nonce="' . $scriptNonce . '">'
            . 'if (window.opener) { window.opener.postMessage(' . $payload . ', ' . $targetOrigin . '); }'
            . 'window.close();'
            . '</script></body></html>',
        );
        $response->headers->set('Content-Security-Policy', "default-src 'none'; script-src 'nonce-" . $scriptNonce . "'");
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    /**
     * "Connect SSO" round trip: bind the IdP identity to the admin who started
     * it (authenticated and user-verified at link/start), then return to the
     * profile page. The only way an existing superadmin gets bound.
     */
    private function completeLink(OidcCallbackResult $result, Context $context): RedirectResponse
    {
        $userId = $result->flow->expectedUserId;
        \assert($userId !== null);

        $this->identityResolver->linkExplicitly(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $userId, $result->identity(), $context);

        $user = $this->connection->fetchAssociative(
            'SELECT `email`, `first_name`, `last_name` FROM `user` WHERE `id` = :id',
            ['id' => Uuid::fromHexToBytes($userId)],
        );

        if (\is_array($user)) {
            $this->eventDispatcher->dispatch(new AccountSsoLinkedEvent(
                Sw6OidcUserProviderEntity::USER_TYPE_ADMIN,
                $userId,
                (string) $user['email'],
                trim($user['first_name'] . ' ' . $user['last_name']),
                $result->provider->getDisplayName() ?: $result->provider->getAppName(),
                null,
                $context,
            ));
        }

        return new RedirectResponse(rtrim($this->administrationBaseUrl, '/') . '/#/sw/profile/index/general?sw6oidc_linked=1');
    }
}
