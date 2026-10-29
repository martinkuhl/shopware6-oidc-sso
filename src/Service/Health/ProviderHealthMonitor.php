<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\NotFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\RangeFilter;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * One health-alert round (HealthCheckAlertTaskHandler): probes every active
 * provider that has alerting configured (threshold > 0 and a webhook URL),
 * advances its HealthAlertState and sends the due webhook. An alert that
 * could not be delivered is not marked as sent, so the next round retries.
 * State is written with DBAL: the columns are WriteProtected for the API.
 */
class ProviderHealthMonitor
{
    /**
     * @param EntityRepository<Sw6OidcProviderCollection> $providerRepository
     */
    public function __construct(
        private readonly EntityRepository $providerRepository,
        private readonly ProviderReachabilityChecker $reachabilityChecker,
        private readonly WebhookNotifier $webhookNotifier,
        private readonly Sw6OidcEncryptor $encryptor,
        private readonly Connection $connection,
        private readonly LoggerInterface $logger,
        private readonly string $shopUrl,
    ) {
    }

    public function run(?\DateTimeImmutable $now = null): void
    {
        $now ??= new \DateTimeImmutable();

        foreach ($this->monitoredProviders() as $provider) {
            try {
                $this->checkProvider($provider, $now);
            } catch (\Throwable $exception) {
                $this->logger->error('sw6oidc: health check round failed for a provider.', [
                    'providerId' => $provider->getId(),
                    'exception' => $exception->getMessage(),
                ]);
            }
        }
    }

    private function checkProvider(Sw6OidcProviderEntity $provider, \DateTimeImmutable $now): void
    {
        $result = $this->reachabilityChecker->check($provider);
        [$state, $notify] = HealthAlertState::fromProvider($provider)->next(
            $result->ok,
            $provider->getHealthAlertFailureThreshold(),
            $provider->isHealthAlertNotifyOnRecovery(),
            $now,
        );

        if ($notify !== null && $this->notify($provider, $notify, $state, $result, $now)) {
            $state = $state->withNotifiedAt($now);
        }

        $this->persist($provider->getId(), $state, $now);
    }

    private function notify(Sw6OidcProviderEntity $provider, string $event, HealthAlertState $state, ReachabilityResult $result, \DateTimeImmutable $now): bool
    {
        $webhookUrl = (string) $provider->getHealthAlertWebhookUrl();

        if ($this->encryptor->isEncrypted($webhookUrl)) {
            $this->logger->error('sw6oidc: health alert webhook URL cannot be decrypted (APP_SECRET changed?); re-enter it.', ['providerId' => $provider->getId()]);

            return false;
        }

        $name = $provider->getDisplayName() ?: $provider->getAppName();
        $text = $event === HealthAlertState::NOTIFY_UNHEALTHY
            ? sprintf(
                '⚠️ OIDC provider "%s" on %s is unreachable (%d consecutive failed checks since %s): %s',
                $name,
                $this->shopUrl,
                $state->consecutiveFailures,
                $state->firstFailureAt?->format(\DATE_ATOM),
                $result->detail,
            )
            : sprintf('✅ OIDC provider "%s" on %s is reachable again.', $name, $this->shopUrl);

        return $this->webhookNotifier->send($webhookUrl, [
            'text' => $text,
            'event' => 'sw6oidc.provider.' . $event,
            'provider' => ['id' => $provider->getId(), 'name' => $name],
            'shop' => $this->shopUrl,
            'consecutiveFailures' => $state->consecutiveFailures,
            'firstFailureAt' => $state->firstFailureAt?->format(\DATE_ATOM),
            'check' => $result->toArray(),
            'timestamp' => $now->format(\DATE_ATOM),
        ]);
    }

    private function persist(string $providerId, HealthAlertState $state, \DateTimeImmutable $now): void
    {
        $format = static fn (?\DateTimeImmutable $date): ?string => $date?->format(Defaults::STORAGE_DATE_TIME_FORMAT);

        $this->connection->executeStatement(
            'UPDATE `sw6oidc_provider` SET
                `health_alert_consecutive_failures` = :failures,
                `health_alert_last_status` = :status,
                `health_alert_last_checked_at` = :checkedAt,
                `health_alert_first_failure_at` = :firstFailureAt,
                `health_alert_last_notified_at` = :notifiedAt
             WHERE `id` = :id',
            [
                'failures' => $state->consecutiveFailures,
                'status' => $state->lastStatus,
                'checkedAt' => $format($now),
                'firstFailureAt' => $format($state->firstFailureAt),
                'notifiedAt' => $format($state->lastNotifiedAt),
                'id' => Uuid::fromHexToBytes($providerId),
            ],
        );
    }

    /**
     * @return list<Sw6OidcProviderEntity>
     */
    private function monitoredProviders(): array
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('isActive', true))
            ->addFilter(new RangeFilter('healthAlertFailureThreshold', [RangeFilter::GT => 0]))
            ->addFilter(new NotFilter(NotFilter::CONNECTION_AND, [new EqualsFilter('healthAlertWebhookUrl', null)]));

        $providers = [];

        foreach ($this->providerRepository->search($criteria, Context::createDefaultContext())->getEntities() as $provider) {
            if ((string) $provider->getHealthAlertWebhookUrl() !== '') {
                $providers[] = $provider;
            }
        }

        return $providers;
    }
}
