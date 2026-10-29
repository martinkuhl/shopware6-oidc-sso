<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\EntityWriteResult;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Core decodes every written field when it builds EntityWrittenEvent
 * payloads, so without this every sw6oidc_provider.written listener (other
 * plugins, app webhooks, logging) would receive the plaintext client secret
 * and webhook URL (N-L6). Runs first and blanks them: a listener still sees
 * *that* the field was written (key present, value ''), never its value.
 *
 * Nested written events are dispatched before their container event, and
 * the container holds the same instances, so this also covers
 * entity.written listeners.
 */
class ProviderSecretPayloadScrubber implements EventSubscriberInterface
{
    public const SECRET_PROPERTIES = ['clientSecret', 'healthAlertWebhookUrl'];

    public static function getSubscribedEvents(): array
    {
        return [
            Sw6OidcProviderDefinition::ENTITY_NAME . '.written' => ['onProviderWritten', \PHP_INT_MAX],
        ];
    }

    public function onProviderWritten(EntityWrittenEvent $event): void
    {
        $changed = false;
        $results = [];

        foreach ($event->getWriteResults() as $result) {
            $payload = $result->getPayload();
            $secrets = array_intersect_key($payload, array_flip(self::SECRET_PROPERTIES));

            if ($secrets === []) {
                $results[] = $result;

                continue;
            }

            $changed = true;
            $results[] = new EntityWriteResult(
                $result->getPrimaryKey(),
                array_merge($payload, array_fill_keys(array_keys($secrets), '')),
                $result->getEntityName(),
                $result->getOperation(),
                $result->getExistence(),
                $result->getChangeSet(),
            );
        }

        if ($changed) {
            $this->replaceWriteResults($event, $results);
        }
    }

    /**
     * EntityWrittenEvent has no setter; its results are a protected,
     * non-readonly property (and getPayloads() caches lazily).
     *
     * @param list<EntityWriteResult> $results
     */
    private function replaceWriteResults(EntityWrittenEvent $event, array $results): void
    {
        (new \ReflectionProperty(EntityWrittenEvent::class, 'writeResults'))->setValue($event, $results);
        (new \ReflectionProperty(EntityWrittenEvent::class, 'payloads'))->setValue($event, null);
    }
}
