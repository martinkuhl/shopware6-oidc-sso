<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets the browser-binding cookie minted while a login flow started (M1).
 */
class BrowserBindingCookieSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly BrowserBinding $browserBinding)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onResponse'];
    }

    public function onResponse(ResponseEvent $event): void
    {
        if ($event->isMainRequest()) {
            $this->browserBinding->applyPendingCookie($event->getRequest(), $event->getResponse());
        }
    }
}
