<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Session\SessionAuthenticationClock;
use Shopware\Core\Checkout\Customer\Event\CustomerLoginEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Every customer login (password, OIDC, passkey: all dispatch core's
 * CustomerLoginEvent) starts a freshly authenticated session (R3-M5).
 */
class CustomerAuthenticationClockSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly SessionAuthenticationClock $clock)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [CustomerLoginEvent::class => 'onLogin'];
    }

    public function onLogin(CustomerLoginEvent $event): void
    {
        $this->clock->markAuthenticated($event->getCustomer()->getId());
    }
}
