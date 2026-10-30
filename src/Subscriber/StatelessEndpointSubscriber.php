<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * The health check and the IdP's back-/front-channel logout calls come from
 * machines without cookies. Core starts a Storefront session for every
 * sales-channel request, so each of them left a throwaway PHP session behind
 * — an uptime monitor every 10 s makes ~8.6k a day (R8-L18). These endpoints
 * read and write no session, so they get an in-memory one: nothing is
 * persisted, no cookie is set.
 *
 * Runs before core's StorefrontSubscriber::startSession() (priority 40),
 * which runs before routing, hence the match on the resolved path.
 */
class StatelessEndpointSubscriber implements EventSubscriberInterface
{
    private const PATHS = ['/sw6oidc/health', '/sw6oidc/backchannel-logout', '/sw6oidc/frontchannel-logout'];

    private const SESSION_NAME = 'SW6OIDC_STATELESS';

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['useMemorySession', 41],
            // After Symfony's session listener (-1000), which announces any started session.
            KernelEvents::RESPONSE => ['dropSessionCookie', -1010],
        ];
    }

    public function useMemorySession(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->isStatelessEndpoint($event->getRequest())) {
            return;
        }

        $event->getRequest()->setSession(new Session(new MockArraySessionStorage(self::SESSION_NAME)));
    }

    public function dropSessionCookie(ResponseEvent $event): void
    {
        if ($event->isMainRequest() && $this->isStatelessEndpoint($event->getRequest())) {
            $event->getResponse()->headers->removeCookie(self::SESSION_NAME);
        }
    }

    private function isStatelessEndpoint(Request $request): bool
    {
        return \in_array(rtrim($request->getPathInfo(), '/'), self::PATHS, true);
    }
}
