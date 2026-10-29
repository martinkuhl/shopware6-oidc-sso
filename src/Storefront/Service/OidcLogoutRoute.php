<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Oidc\LogoutContext;
use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use MartinKuhl\Sw6Oidc\Service\Oidc\RpInitiatedLogoutService;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Decorates core's LogoutRoute to resolve the IdP's RP-Initiated Logout URL
 * for customers who logged in via OIDC.
 *
 * This has to happen here rather than in a CustomerLogoutEvent listener: core
 * LogoutRoute replaces the sales-channel context with a fresh random token
 * *before* dispatching that event, so the event no longer carries the token
 * the session registry entry was registered under at login. We capture it
 * before delegating and only consume the entry once the logout succeeded.
 *
 * The resolved URL is only handed to PendingLogoutRedirect; turning it into
 * a redirect is CustomerLogoutSubscriber's job (Storefront route only, so
 * Store API clients keep their JSON response).
 */
class OidcLogoutRoute extends AbstractLogoutRoute
{
    public function __construct(
        private readonly AbstractLogoutRoute $decorated,
        private readonly ProviderResolver $providerResolver,
        private readonly RpInitiatedLogoutService $rpInitiatedLogoutService,
        private readonly PendingLogoutRedirect $pendingLogoutRedirect,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
    ) {
    }

    public function getDecorated(): AbstractLogoutRoute
    {
        return $this->decorated;
    }

    public function logout(SalesChannelContext $context, RequestDataBag $data): ContextTokenResponse
    {
        $preLogoutToken = $context->getToken();
        $customerId = $context->getCustomer()?->getId();

        $response = $this->decorated->logout($context, $data);

        if ($customerId === null) {
            return $response;
        }

        // The session is over locally: a later Back-/Front-Channel Logout has
        // nothing left to end for it.
        $session = $this->sessionRegistry->findBySessionKey(Sw6OidcSession::USER_TYPE_CUSTOMER, $customerId, $preLogoutToken);

        if ($session instanceof Sw6OidcSession) {
            $this->sessionRegistry->remove($session);
        }

        $this->activityRecorder->recordLogout(
            Sw6OidcSession::USER_TYPE_CUSTOMER,
            $customerId,
            Sw6OidcSessionActivityDefinition::LOGOUT_REASON_LOGOUT,
            $preLogoutToken,
            $session?->id,
        );

        if (!$session instanceof Sw6OidcSession) {
            $this->logger->debug('sw6oidc: no OIDC session registered for this customer session, skipping RP-initiated logout.');

            return $response;
        }

        $logoutContext = new LogoutContext($session->providerId, $session->idToken, $session->idpAccessToken, $session->idpRefreshToken);

        try {
            $provider = $this->providerResolver->getActiveById($logoutContext->providerId, LoginType::Customer->value, $context->getContext());
        } catch (ProviderNotFoundException $exception) {
            $this->logger->warning('sw6oidc: RP-initiated logout skipped, provider no longer active.', [
                'providerId' => $logoutContext->providerId,
                'exception' => $exception->getMessage(),
            ]);

            return $response;
        }

        $this->rpInitiatedLogoutService->revokeTokens($provider, $logoutContext);

        $logoutUrl = $this->rpInitiatedLogoutService->buildLogoutUrl(
            $provider,
            $logoutContext->idToken,
            $this->urlGenerator->generate('frontend.account.login.page', [], UrlGeneratorInterface::ABSOLUTE_URL),
            PostLogoutState::TARGET_CUSTOMER,
        );

        $this->logger->debug('sw6oidc: resolved customer RP-initiated logout URL.', [
            'providerId' => $logoutContext->providerId,
            'hasLogoutUrl' => $logoutUrl !== null,
        ]);

        $this->pendingLogoutRedirect->set($logoutUrl);

        // Store API clients (headless) get the IdP logout URL in the response
        // body's redirectUrl, since they aren't redirected by the Storefront.
        return $logoutUrl !== null ? new ContextTokenResponse($response->getToken(), $logoutUrl) : $response;
    }
}
