<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyConfigException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingPartyResolver;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SystemConfig\Event\BeforeSystemConfigChangedEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Refuses a passkey RP ID that can't work where it applies (R3-M8): the
 * browser only accepts an RP ID that is the page's host or one of its
 * parent domains, so a wrong value silently breaks every passkey there.
 *
 * - Administration RP ID: must cover the host of APP_URL.
 * - Storefront RP ID: must cover a domain of every sales channel it applies
 *   to (the one it is saved for, or all of them for the global value).
 */
class PasskeyRpIdConfigValidator implements EventSubscriberInterface
{
    public function __construct(
        private readonly Connection $connection,
        private readonly string $appUrl,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [BeforeSystemConfigChangedEvent::class => 'validate'];
    }

    public function validate(BeforeSystemConfigChangedEvent $event): void
    {
        $value = $event->getValue();

        if (!\is_string($value) || trim($value) === '') {
            return;
        }

        if ($event->getKey() === PasskeyConfig::KEY_RP_ID_ADMIN) {
            $host = (string) parse_url($this->appUrl, PHP_URL_HOST);

            if (!PasskeyRelyingPartyResolver::covers($value, $host)) {
                throw PasskeyConfigException::rpIdDoesNotCoverHosts($value, [$host]);
            }

            return;
        }

        if ($event->getKey() !== PasskeyConfig::KEY_RP_ID) {
            return;
        }

        foreach ($this->hostsByChannel($event->getSalesChannelId()) as $hosts) {
            if (array_filter($hosts, static fn (string $host): bool => PasskeyRelyingPartyResolver::covers($value, $host)) === []) {
                throw PasskeyConfigException::rpIdDoesNotCoverHosts($value, $hosts);
            }
        }
    }

    /**
     * @return array<string, list<string>> sales channel id => domain hosts
     */
    private function hostsByChannel(?string $salesChannelId): array
    {
        $sql = 'SELECT LOWER(HEX(`sales_channel_id`)) AS `channel`, `url` FROM `sales_channel_domain`';
        $parameters = [];
        $types = [];

        if ($salesChannelId !== null) {
            $sql .= ' WHERE `sales_channel_id` = :id';
            $parameters['id'] = Uuid::fromHexToBytes($salesChannelId);
            $types['id'] = ParameterType::BINARY;
        }

        $hosts = [];

        foreach ($this->connection->fetchAllAssociative($sql, $parameters, $types) as $row) {
            $host = parse_url((string) $row['url'], PHP_URL_HOST);

            if (\is_string($host) && $host !== '') {
                $hosts[(string) $row['channel']][] = strtolower($host);
            }
        }

        return array_map(static fn (array $list): array => array_values(array_unique($list)), $hosts);
    }
}
