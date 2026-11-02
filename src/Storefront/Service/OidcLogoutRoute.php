<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use MartinKuhl\Sw6Oidc\Service\Oidc\RpInitiatedLogoutService;
use MartinKuhl\Sw6Oidc\Service\Session\SessionDevice;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionTokenRevoker;
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
 * (and this browser's device cookie) before delegating and only consume the
 * entries once the logout succeeded.
 *
 * The resolved URL is only handed to PendingLogoutRedirect; turning it into
 * a redirect is CustomerLogoutSubscriber's job (Storefront route only, so
 * Store API clients keep their JSON response).
 */
class OidcLogoutRoute extends AbstractLogoutRoute
{
    public function __construct(
        private readonly AbstractLogoutRoute $decorated,
        private readonly RpInitiatedLogoutService $rpInitiatedLogoutService,
        private readonly PendingLogoutRedirect $pendingLogoutRedirect,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly Sw6OidcSessionTokenRevoker $tokenRevoker,
        private readonly SessionDevice $sessionDevice,
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
        $device = $this->sessionDevice->currentDevice();

        $response = $this->decorated->logout($context, $data);

        if ($customerId === null) {
            return $response;
        }

        // The context token is over locally, and with it every SSO login that
        // shared it (logins on several devices get the same token, R8-M9): a
        // later Back-/Front-Channel Logout has nothing left to end for them.
        $sessions = $this->sessionRegistry->findAllBySessionKey(Sw6OidcSession::USER_TYPE_CUSTOMER, $customerId, $preLogoutToken);
        $primary = $this->loginOfThisDevice($sessions, $device);

        foreach ($sessions as $session) {
            $this->sessionRegistry->remove($session);
        }

        $this->activityRecorder->recordLogout(
            Sw6OidcSession::USER_TYPE_CUSTOMER,
            $customerId,
            Sw6OidcSessionActivityDefinition::LOGOUT_REASON_LOGOUT,
            $preLogoutToken,
            $primary?->id,
        );

        if (!$primary instanceof Sw6OidcSession) {
            $this->logger->debug('sw6oidc: no OIDC session registered for this customer session, skipping RP-initiated logout.');

            return $response;
        }

        $provider = null;

        foreach ($sessions as $session) {
            $sessionProvider = $this->tokenRevoker->revoke($session, $context->getContext());

            if ($session === $primary) {
                $provider = $sessionProvider;
            }
        }

        if (!$provider instanceof Sw6OidcProviderEntity) {
            return $response;
        }

        $logoutUrl = $this->rpInitiatedLogoutService->buildLogoutUrl(
            $provider,
            $primary->idToken,
            $this->urlGenerator->generate('frontend.account.login.page', [], UrlGeneratorInterface::ABSOLUTE_URL),
            PostLogoutState::TARGET_CUSTOMER,
        );

        $this->logger->debug('sw6oidc: resolved customer RP-initiated logout URL.', [
            'providerId' => $primary->providerId,
            'hasLogoutUrl' => $logoutUrl !== null,
            'loginOfThisDevice' => $device !== null && $primary->deviceHash === $device,
        ]);

        $this->pendingLogoutRedirect->set($logoutUrl);

        // Store API clients (headless) get the IdP logout URL in the response
        // body's redirectUrl, since they aren't redirected by the Storefront.
        return $logoutUrl !== null ? new ContextTokenResponse($response->getToken(), $logoutUrl) : $response;
    }

    /**
     * The IdP logout is for the login made in this browser (its device
     * cookie), else for the newest login, the one most likely made here
     * (Store API clients send no cookie).
     *
     * @param list<Sw6OidcSession> $sessions newest first
     */
    private function loginOfThisDevice(array $sessions, ?string $device): ?Sw6OidcSession
    {
        if ($device !== null) {
            foreach ($sessions as $session) {
                if ($session->deviceHash !== null && hash_equals($session->deviceHash, $device)) {
                    return $session;
                }
            }
        }

        return $sessions[0] ?? null;
    }
}
