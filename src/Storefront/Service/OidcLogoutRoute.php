<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
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

        // The context token is over locally, and with it every SSO login that
        // shared it (logins on several devices get the same token, R8-M9): a
        // later Back-/Front-Channel Logout has nothing left to end for them.
        $sessions = $this->sessionRegistry->findAllBySessionKey(Sw6OidcSession::USER_TYPE_CUSTOMER, $customerId, $preLogoutToken);

        foreach ($sessions as $session) {
            $this->sessionRegistry->remove($session);
        }

        $this->activityRecorder->recordLogout(
            Sw6OidcSession::USER_TYPE_CUSTOMER,
            $customerId,
            Sw6OidcSessionActivityDefinition::LOGOUT_REASON_LOGOUT,
            $preLogoutToken,
            $sessions[0]->id ?? null,
        );

        if ($sessions === []) {
            $this->logger->debug('sw6oidc: no OIDC session registered for this customer session, skipping RP-initiated logout.');

            return $response;
        }

        $providers = [];

        foreach ($sessions as $index => $session) {
            try {
                $providers[$index] = $this->providerResolver->getActiveById($session->providerId, LoginType::Customer->value, $context->getContext());
            } catch (ProviderNotFoundException $exception) {
                $this->logger->warning('sw6oidc: token revocation skipped, provider no longer active.', [
                    'providerId' => $session->providerId,
                    'exception' => $exception->getMessage(),
                ]);

                continue;
            }

            $this->rpInitiatedLogoutService->revokeTokens($providers[$index], $this->logoutContextOf($session));
        }

        // The IdP logout is for the newest login: the one most likely made in this browser.
        $logoutContext = $this->logoutContextOf($sessions[0]);
        $provider = $providers[0] ?? null;

        if (!$provider instanceof Sw6OidcProviderEntity) {
            return $response;
        }

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

    private function logoutContextOf(Sw6OidcSession $session): LogoutContext
    {
        return new LogoutContext($session->providerId, $session->idToken, $session->idpAccessToken, $session->idpRefreshToken);
    }
}
