<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use MartinKuhl\Sw6Oidc\Service\Session\SessionDevice;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets the cookies minted during a request: the browser binding of a login
 * flow start (M1) and the device cookie of a Storefront SSO login.
 */
class PendingCookieSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly BrowserBinding $browserBinding,
        private readonly SessionDevice $sessionDevice,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onResponse'];
    }

    public function onResponse(ResponseEvent $event): void
    {
        if ($event->isMainRequest()) {
            $this->browserBinding->applyPendingCookie($event->getRequest(), $event->getResponse());
            $this->sessionDevice->applyPendingCookie($event->getRequest(), $event->getResponse());
        }
    }
}
