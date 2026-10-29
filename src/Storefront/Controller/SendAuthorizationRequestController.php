<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Controller;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthorizationRequestBuilder;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\RelayStateValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Session\SessionAuthenticationClock;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Psr\Log\LoggerInterface;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Step 1 of the Storefront customer OIDC flow: redirects to the IdP.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class SendAuthorizationRequestController extends StorefrontController
{
    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly AuthorizationRequestBuilder $requestBuilder,
        private readonly LoggerInterface $logger,
        private readonly UserProviderBindingService $bindingService,
        private readonly AbstractLogoutRoute $logoutRoute,
        private readonly RelayStateValidator $relayStateValidator,
        private readonly Sw6OidcRateLimiter $rateLimiter,
        private readonly SessionAuthenticationClock $authenticationClock,
    ) {
    }

    /** Where a re-authentication may return to: `target` query value => route. */
    private const REAUTH_TARGETS = [
        'passkey' => 'frontend.account.passkey.page',
        'profile' => 'frontend.account.profile.page',
    ];

    #[Route(
        path: '/sw6oidc/login',
        name: 'frontend.sw6oidc.login',
        defaults: ['_loginRequired' => false],
        methods: ['GET'],
    )]
    public function login(Request $request, SalesChannelContext $context): RedirectResponse
    {
        // Every flow start stores a flow context: a consuming budget (N-M15).
        if (!$this->rateLimiter->consume(Sw6OidcRateLimiter::SCOPE_FLOW_START, $request->getClientIp())) {
            $this->logger->warning('sw6oidc: customer SSO flow start rate-limited.');
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.failed'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        }

        $providerId = $request->query->get('providerId');
        $relayState = $this->relayStateValidator->resolve(
            (string) $request->query->get('redirectTo', ''),
            $request->query->get('redirectParameters'),
        ) ?? $this->generateUrl('frontend.account.home.page');

        try {
            $provider = $providerId !== null
                ? $this->providerResolver->getActiveById((string) $providerId, LoginType::Customer->value, $context->getContext())
                : $this->providerResolver->resolveDefault(LoginType::Customer->value, $context->getContext());
        } catch (ProviderNotFoundException $exception) {
            $this->logger->warning('sw6oidc: SSO login requested but no active provider is configured.', [
                'exception' => $exception->getMessage(),
            ]);

            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.providerUnavailable'));

            return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
        }

        $redirectUri = $this->generateUrl('frontend.sw6oidc.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
        $authorizeUrl = $this->requestBuilder->build($provider, LoginType::Customer->value, $relayState, $redirectUri);

        $response = new RedirectResponse($authorizeUrl);
        // Every flow start stores a one-time token: keep crawlers away (R3-M17).
        $response->headers->set('X-Robots-Tag', 'noindex, nofollow');

        return $response;
    }

    /**
     * "Connect SSO" from the logged-in account: an OIDC round trip whose
     * callback binds the IdP identity to exactly this customer (see
     * OidcCallbackController::completeLink()). The only way to connect an
     * existing account when the provider doesn't link by email.
     *
     * A binding is a permanent way in that survives password changes, so it
     * needs a freshly authenticated session, like adding a passkey: a stolen
     * session alone must not attach the attacker's IdP account (R3-H6).
     */
    #[Route(
        path: '/sw6oidc/link',
        name: 'frontend.sw6oidc.link',
        defaults: ['_loginRequired' => true],
        methods: ['POST'],
    )]
    public function link(Request $request, SalesChannelContext $context): RedirectResponse
    {
        $customer = $context->getCustomer();
        \assert($customer instanceof \Shopware\Core\Checkout\Customer\CustomerEntity);

        if (!$this->authenticationClock->isFresh($context)) {
            return new RedirectResponse($this->generateUrl('frontend.sw6oidc.reauth', ['target' => 'profile']));
        }

        try {
            $provider = $this->providerResolver->getActiveById((string) $request->request->get('providerId'), LoginType::Customer->value, $context->getContext());
        } catch (ProviderNotFoundException) {
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.login.providerUnavailable'));

            return new RedirectResponse($this->generateUrl('frontend.account.profile.page'));
        }

        $redirectUri = $this->generateUrl('frontend.sw6oidc.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);

        return new RedirectResponse($this->requestBuilder->build(
            $provider,
            'customer',
            '',
            $redirectUri,
            AuthorizationFlowContext::PURPOSE_LINK,
            $customer->getId(),
        ));
    }

    /**
     * Fresh login before a sensitive account change (adding a passkey,
     * connecting SSO): an SSO-connected customer goes through their provider
     * with `prompt=login` (a `reauth` flow: the callback checks
     * `auth_time` and the subject, then marks this session fresh, R3-M5);
     * anybody else is logged out and asked to log in again. Either way they
     * come back to the page named by `target` (passkey page by default).
     */
    #[Route(
        path: '/sw6oidc/reauth',
        name: 'frontend.sw6oidc.reauth',
        defaults: ['_loginRequired' => true],
        methods: ['GET'],
    )]
    public function reauthenticate(Request $request, SalesChannelContext $context): RedirectResponse
    {
        $customer = $context->getCustomer();
        \assert($customer instanceof \Shopware\Core\Checkout\Customer\CustomerEntity);

        $targetRoute = self::REAUTH_TARGETS[(string) $request->query->get('target', '')] ?? self::REAUTH_TARGETS['passkey'];
        $providerId = $this->bindingService->getBoundProviderId(LoginType::Customer->value, $customer->getId(), $context->getContext());

        if ($providerId !== null) {
            try {
                $provider = $this->providerResolver->getActiveById($providerId, LoginType::Customer->value, $context->getContext());

                return new RedirectResponse($this->requestBuilder->build(
                    $provider,
                    'customer',
                    $this->generateUrl($targetRoute),
                    $this->generateUrl('frontend.sw6oidc.callback', [], UrlGeneratorInterface::ABSOLUTE_URL),
                    AuthorizationFlowContext::PURPOSE_REAUTH,
                    $customer->getId(),
                    ['prompt' => 'login'],
                ));
            } catch (ProviderNotFoundException) {
                // Provider gone: fall back to a normal re-login.
            }
        }

        $this->logoutRoute->logout($context, new RequestDataBag());

        if ($request->hasSession()) {
            $request->getSession()->invalidate();
        }

        $this->addFlash(self::INFO, $this->trans('sw6oidc.account.reauthRequired'));

        return new RedirectResponse($this->generateUrl('frontend.account.login.page', ['redirectTo' => $targetRoute]));
    }
}
