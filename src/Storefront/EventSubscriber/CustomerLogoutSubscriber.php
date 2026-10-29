<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\EventSubscriber;

use MartinKuhl\Sw6Oidc\Storefront\Service\PendingLogoutRedirect;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * RP-Initiated Logout for Storefront customers: redirects to the IdP's
 * end_session_endpoint after a customer logs out.
 *
 * Two-step because the logout route itself cannot replace the controller's
 * HTTP response: OidcLogoutRoute (decorating core's LogoutRoute) resolves
 * the IdP logout URL while the logout runs, and this listener rewrites the
 * Storefront logout controller's redirect to that URL afterwards. Limited to
 * the Storefront logout page — a Store API logout must keep its JSON body.
 */
class CustomerLogoutSubscriber implements EventSubscriberInterface
{
    private const STOREFRONT_LOGOUT_ROUTE = 'frontend.account.logout.page';

    public function __construct(private readonly PendingLogoutRedirect $pendingLogoutRedirect)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $logoutUrl = $this->pendingLogoutRedirect->pull();

        if ($logoutUrl === null || $event->getRequest()->attributes->get('_route') !== self::STOREFRONT_LOGOUT_ROUTE) {
            return;
        }

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
