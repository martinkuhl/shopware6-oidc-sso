<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Health;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderHealthMonitor;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderReachabilityChecker;
use MartinKuhl\Sw6Oidc\Service\Health\WebhookNotifier;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Runs whole monitoring rounds against a simulated provider row: the
 * persisted state of one round is fed into the next, like the database does.
 */
#[CoversClass(ProviderHealthMonitor::class)]
final class ProviderHealthMonitorTest extends TestCase
{
    /** @var array<string, mixed> the provider row, updated by persist() */
    private array $row = [];

    private bool $idpUp = false;

    private bool $webhookUp = true;

    /** @var list<array<string, mixed>> */
    private array $webhookCalls = [];

    protected function setUp(): void
    {
        $this->row = [
            'id' => '0190a1b2c3d4e5f60718293a4b5c6d7e',
            'appName' => 'keycloak',
            'displayName' => 'Keycloak',
            'jwksEndpoint' => 'https://idp.example/jwks',
            'httpTimeout' => 5,
            'healthAlertWebhookUrl' => 'https://hooks.example/abc',
            'healthAlertFailureThreshold' => 2,
            'healthAlertNotifyOnRecovery' => true,
        ];
    }

    public function testOutageIsAlertedOnceAndRecoveryAnnounced(): void
    {
        foreach ([false, false, false, false, true, true] as $minute => $up) {
            $this->idpUp = $up;
            $this->round($minute);
        }

        self::assertSame(['sw6oidc.provider.unhealthy', 'sw6oidc.provider.recovered'], array_column($this->webhookCalls, 'event'));
        self::assertSame(2, $this->webhookCalls[0]['consecutiveFailures']);
        self::assertStringContainsString('Keycloak', $this->webhookCalls[0]['text']);
        self::assertSame('ok', $this->row['healthAlertLastStatus']);
        self::assertSame(0, $this->row['healthAlertConsecutiveFailures']);
    }

    public function testFailedDeliveryIsRetriedOnTheNextRound(): void
    {
        $this->webhookUp = false;
        $this->round(0);
        $this->round(1);
        self::assertNull($this->row['healthAlertLastNotifiedAt'], 'nothing was delivered');

        $this->webhookUp = true;
        $this->round(2);

        self::assertCount(2, $this->webhookCalls, 'due from round 1 (threshold 2): failed at 1, delivered at 2');
        self::assertNotNull($this->row['healthAlertLastNotifiedAt']);
    }

    public function testAdminEditMidOutageDoesNotReFire(): void
    {
        $this->round(0);
        $this->round(1);
        self::assertCount(1, $this->webhookCalls);

        // The admin lowers the threshold; the API cannot touch the state columns.
        $this->row['healthAlertFailureThreshold'] = 1;
        $this->round(2);
        $this->round(3);

        self::assertCount(1, $this->webhookCalls);
    }

    private function round(int $minute): void
    {
        $idp = new MockHttpClient(fn (): MockResponse => $this->idpUp ? new MockResponse('{"keys":[{"kty":"RSA"}]}') : new MockResponse('', ['http_code' => 503]));
        $hooks = new MockHttpClient(function (string $method, string $url, array $options): MockResponse {
            $this->webhookCalls[] = json_decode((string) $options['body'], true, 512, JSON_THROW_ON_ERROR);

            return new MockResponse('ok', ['http_code' => $this->webhookUp ? 200 : 500]);
        });
        $ssrf = new SsrfUrlValidator(false, static fn (): array => ['93.184.215.14']);

        $monitor = new ProviderHealthMonitor(
            $this->repository(),
            new ProviderReachabilityChecker($idp, $ssrf),
            new WebhookNotifier($hooks, $ssrf, new NullLogger()),
            $this->connection(),
            new NullLogger(),
            'https://shop.example',
        );

        $monitor->run(new \DateTimeImmutable(sprintf('2026-01-01 10:%02d:00', $minute)));
    }

    private function repository(): EntityRepository
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context): EntitySearchResult {
            $provider = new Sw6OidcProviderEntity();
            $provider->assign($this->row);

            return new EntitySearchResult(Sw6OidcProviderDefinition::ENTITY_NAME, 1, new Sw6OidcProviderCollection([$provider]), null, $criteria, $context);
        });

        return $repository;
    }

    private function connection(): Connection
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('executeStatement')->willReturnCallback(function (string $sql, array $params): int {
            $date = static fn (?string $value): ?\DateTimeImmutable => $value === null ? null : new \DateTimeImmutable($value);

            $this->row['healthAlertConsecutiveFailures'] = $params['failures'];
            $this->row['healthAlertLastStatus'] = $params['status'];
            $this->row['healthAlertLastCheckedAt'] = $date($params['checkedAt']);
            $this->row['healthAlertFirstFailureAt'] = $date($params['firstFailureAt']);
            $this->row['healthAlertLastNotifiedAt'] = $date($params['notifiedAt']);

            return 1;
        });

        return $connection;
    }
}
