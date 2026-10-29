<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Controller;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AccountSsoLinkedEvent;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthTimeValidator;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackProcessor;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerSalesChannelBinding;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\CustomerProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\IdentityResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\UnknownStateException;
use MartinKuhl\Sw6Oidc\Service\Security\RelayStateValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Session\SessionAuthenticationClock;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextService;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextServiceParameters;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Step 2 of the Storefront customer OIDC flow: exchanges the code, verifies
 * the id_token, JIT-provisions the customer, and logs them in — one
 * controller, since the Storefront callback is already a server-rendered
 * HTTP context (no nonce hand-off as in the Administration).
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class OidcCallbackController extends StorefrontController
{
    public function __construct(
        private readonly OidcCallbackProcessor $callbackProcessor,
        private readonly CustomerProvisioningService $customerProvisioningService,
        private readonly AccountService $accountService,
        private readonly SalesChannelContextService $salesChannelContextService,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcRateLimiter $rateLimiter,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly IdentityResolver $identityResolver,
        private readonly RelayStateValidator $relayStateValidator,
        private readonly SessionAuthenticationClock $authenticationClock,
        private readonly UserProviderBindingService $bindingService,
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    #[Route(
        path: '/sw6oidc/callback',
        name: 'frontend.sw6oidc.callback',
        defaults: ['_loginRequired' => false],
        methods: ['GET'],
    )]
    public function callback(Request $request, SalesChannelContext $context): Response
    {
        if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_CALLBACK_STOREFRONT, $request->getClientIp())) {
            $this->logger->warning('sw6oidc: customer OIDC callback rate-limited.');
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.failed'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        }

        if ($request->query->get('error') !== null) {
            $flow = $this->callbackProcessor->abortFlowWithIdpError($request->query->get('state'), Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER);

            if (!$flow instanceof AuthorizationFlowContext) {
                // No flow of this browser: possibly forged, so it counts (R4-L4).
                $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_CALLBACK_STOREFRONT, $request->getClientIp());
            }

            $this->logger->notice(
                'sw6oidc: IdP returned an OAuth error on the customer callback.',
                OidcCallbackProcessor::idpErrorLogContext($request->query->get('error'), $request->query->get('error_description'))
                + ['knownFlow' => $flow instanceof AuthorizationFlowContext],
            );

            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.failed'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        }

        $redirectUri = $this->generateUrl('frontend.sw6oidc.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);

        try {
            $result = $this->callbackProcessor->process(
                $request->query->get('code'),
                $request->query->get('state'),
                $redirectUri,
                Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER,
                $context->getContext(),
            );

            if ($result->flow->purpose === AuthorizationFlowContext::PURPOSE_LINK) {
                return $this->completeLink($result, $context);
            }

            if ($result->flow->purpose === AuthorizationFlowContext::PURPOSE_REAUTH) {
                return $this->completeReauthentication($result, $context);
            }

            if ($result->flow->purpose !== AuthorizationFlowContext::PURPOSE_LOGIN) {
                throw new InvalidStateException(sprintf('Unsupported flow purpose "%s" on the customer callback.', $result->flow->purpose));
            }

            $customer = $this->customerProvisioningService->findOrCreateCustomer($result->provider, $result->profile, $result->identity(), $context);

            // Core's own login by id (events, cart restore, lastLogin), not a copy of it (R4-L5).
            CustomerSalesChannelBinding::assertCanLogIn($customer, $context->getSalesChannelId());
            $contextToken = $this->accountService->loginById($customer->getId(), $context);

            $newContext = $this->salesChannelContextService->get(new SalesChannelContextServiceParameters(
                $context->getSalesChannelId(),
                $contextToken,
                $context->getLanguageIdChain()[0] ?? $context->getLanguageId(),
                $context->getCurrencyId(),
                $context->getDomainId(),
                $context->getContext(),
            ));

            // Lets Shopware's own context-token subscriber persist the new
            // sw-context-token cookie on this response, exactly as a normal
            // login would — no manual cookie handling needed here.
            $request->attributes->set(PlatformRequest::ATTRIBUTE_SALES_CHANNEL_CONTEXT_OBJECT, $newContext);

            // The customer is logged in from here on: a bookkeeping failure
            // must not turn that into "login failed" and a counted failure (R3-L27).
            try {
                $registrySession = $this->sessionRegistry->register(
                    $result->provider->getId(),
                    $result->identity()->subject,
                    $result->sessionId(),
                    Sw6OidcSession::USER_TYPE_CUSTOMER,
                    $customer->getId(),
                    $contextToken,
                    $context->getSalesChannelId(),
                    $result->idToken(),
                    $result->idpAccessToken(),
                    $result->idpRefreshToken(),
                );
            } catch (\Throwable $exception) {
                $registrySession = null;
                $this->logger->error('sw6oidc: the customer is logged in, but the session could not be registered; IdP-initiated logout won\'t reach it.', [
                    'customerId' => $customer->getId(),
                    'exceptionClass' => $exception::class,
                    'exception' => $exception->getMessage(),
                ]);
            }

            $this->activityRecorder->recordLogin(
                Sw6OidcSession::USER_TYPE_CUSTOMER,
                $customer->getId(),
                Sw6OidcSessionActivityDefinition::LOGIN_METHOD_OIDC,
                $contextToken,
                $request,
                $result->provider->getId(),
                $registrySession,
            );

            // Validated again: the stored value is what the login link carried.
            return new RedirectResponse($this->relayStateValidator->safePath($result->flow->relayState) ?? $this->generateUrl('frontend.account.home.page'));
        } catch (AccessControlDeniedException $exception) {
            // Already logged by the evaluator. Plain text only: flash messages render through sw_sanitize.
            $this->addFlash(self::DANGER, $exception->getDisplayMessage() ?? $this->trans('sw6oidc.login.accessDenied'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        } catch (AccountLinkingRequiredException | EmailNotVerifiedException | ProviderMismatchException | SubjectAlreadyLinkedException $exception) {
            // A legitimate user hitting an account policy — not a failure that counts towards the rate limit.
            $this->logger->notice('sw6oidc: customer OIDC login refused by the account policy.', [
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
            ]);

            $this->addFlash(self::DANGER, $this->trans(match (true) {
                $exception instanceof AccountLinkingRequiredException => 'sw6oidc.login.linkRequired',
                $exception instanceof EmailNotVerifiedException => 'sw6oidc.login.emailNotVerified',
                default => 'sw6oidc.login.providerMismatch',
            }));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        } catch (CustomerProvisioningDeniedException $exception) {
            // No account and auto-create off, or the account belongs to another
            // sales channel: an account policy, not a failure to count (R3-L24).
            $this->logger->notice('sw6oidc: customer OIDC login refused, no usable account.', ['exception' => $exception->getMessage()]);
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.accountUnavailable'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        } catch (UnknownStateException $exception) {
            // Expired/reused state (back button, second tab) or junk: not counted (N-M3).
            $this->logger->notice('sw6oidc: customer OIDC callback with an unknown state.', ['exception' => $exception->getMessage()]);
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.failed'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        } catch (\Throwable $exception) {
            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_CALLBACK_STOREFRONT, $request->getClientIp());
            $this->logger->warning('sw6oidc: customer OIDC callback failed.', [
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
                'previousException' => $exception->getPrevious()?->getMessage(),
            ]);

            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.failed'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        }
    }

    /**
     * "Connect SSO" round trip: bind the IdP identity to the customer who
     * started it — and only if that customer is still the one logged in.
     */
    private function completeLink(OidcCallbackResult $result, SalesChannelContext $context): Response
    {
        $customer = $context->getCustomer();

        if (!$customer instanceof \Shopware\Core\Checkout\Customer\CustomerEntity || $customer->getId() !== $result->flow->expectedUserId) {
            throw new InvalidStateException('The "Connect SSO" flow was started by a different customer session.');
        }

        // A channel-bound customer is bound in its channel's scope (R3-M14).
        $this->identityResolver->linkExplicitly(
            Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER,
            $customer->getId(),
            $result->identity(),
            $context->getContext(),
            $customer->getBoundSalesChannelId(),
        );

        $this->eventDispatcher->dispatch(new AccountSsoLinkedEvent(
            Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER,
            $customer->getId(),
            $customer->getEmail(),
            trim($customer->getFirstName() . ' ' . $customer->getLastName()),
            $result->provider->getDisplayName() ?: $result->provider->getAppName(),
            $context->getSalesChannelId(),
            $context->getContext(),
        ));

        $this->addFlash(self::SUCCESS, $this->trans('sw6oidc.account.linkSuccess'));

        return new RedirectResponse($this->generateUrl('frontend.account.profile.page'));
    }

    /**
     * Re-authentication round trip (`/sw6oidc/reauth`): the IdP must confirm
     * a fresh login (`auth_time`) of the identity bound to the customer who
     * started it, still logged in here. Then *this* session counts as freshly
     * authenticated (R3-M5); nobody is logged in or out.
     */
    private function completeReauthentication(OidcCallbackResult $result, SalesChannelContext $context): Response
    {
        $customer = $context->getCustomer();

        if (!$customer instanceof \Shopware\Core\Checkout\Customer\CustomerEntity || $customer->getId() !== $result->flow->expectedUserId) {
            throw new InvalidStateException('The re-authentication was started by a different customer session.');
        }

        AuthTimeValidator::assertFresh($result);

        $identity = $result->identity();
        $owner = $this->bindingService->findUserIdBySubject(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $identity, $context->getContext(), $context->getSalesChannelId());

        if ($owner !== $customer->getId()) {
            throw new InvalidStateException('The re-authentication was performed with a different identity.');
        }

        $this->authenticationClock->markAuthenticated($customer->getId());

        return new RedirectResponse($this->relayStateValidator->safePath($result->flow->relayState) ?? $this->generateUrl('frontend.account.home.page'));
    }
}
