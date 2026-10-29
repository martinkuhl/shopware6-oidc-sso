<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Event\AccountSsoLinkedEvent;
use MartinKuhl\Sw6Oidc\Event\PasskeyRegisteredEvent;
use Shopware\Core\Framework\Event\BusinessEventCollector;
use Shopware\Core\Framework\Event\BusinessEventCollectorEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Makes the plugin's flow events selectable as Flow Builder triggers.
 */
class BusinessEventSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly BusinessEventCollector $collector)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [BusinessEventCollectorEvent::NAME => 'onCollect'];
    }

    public function onCollect(BusinessEventCollectorEvent $event): void
    {
        foreach ([PasskeyRegisteredEvent::class, AccountSsoLinkedEvent::class] as $class) {
            $definition = $this->collector->define($class);

            if ($definition instanceof \Shopware\Core\Framework\Event\BusinessEventDefinition) {
                $event->getCollection()->set($definition->getName(), $definition);
            }
        }
    }
}
