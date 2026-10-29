<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller;

use MartinKuhl\Sw6Oidc\Controller\HealthCheckController;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Health\InfrastructureInspector;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderConfigInspector;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\HttpClientInterface;

#[CoversClass(HealthCheckController::class)]
final class HealthCheckControllerTest extends TestCase
{
    /** @var list<string> */
    private array $infrastructureWarnings = [];

    public function testHasNoWayToMakeOutboundCalls(): void
    {
        foreach ((new \ReflectionClass(HealthCheckController::class))->getConstructor()?->getParameters() ?? [] as $parameter) {
            $type = (string) $parameter->getType();
            self::assertNotSame(HttpClientInterface::class, $type);
            self::assertStringNotContainsString('Reachability', $type);
        }
    }

    public function testOkWhenAllActiveProvidersAreCompleteAndReachable(): void
    {
        [$status, $body] = $this->health([$this->provider([]), $this->monitored('ok')]);

        self::assertSame(200, $status);
        self::assertSame('ok', $body['status']);
        self::assertSame(2, $body['activeProviders']);
    }

    public function testDegradedIsNot503WhileAnotherProviderStillWorks(): void
    {
        [$status, $body] = $this->health([$this->provider(['jwksEndpoint' => null]), $this->monitored('fail'), $this->provider([])]);

        self::assertSame(200, $status);
        self::assertSame('degraded', $body['status']);
        self::assertSame(1, $body['incompleteProviders']);
        self::assertSame(1, $body['unreachableProviders']);
        self::assertStringNotContainsString('idp.example', (string) json_encode($body), 'no URLs or names leak');
    }

    public function testDownWhenNoProviderIsUsable(): void
    {
        [$status, $body] = $this->health([$this->provider(['jwksEndpoint' => null]), $this->monitored('fail')]);

        self::assertSame(503, $status);
        self::assertSame('down', $body['status']);
    }

    public function testUnmonitoredProvidersIgnoreAFrozenFailure(): void
    {
        // Alerting turned off while the last probe failed (N-M14).
        [$status, $body] = $this->health([$this->provider(['healthAlertLastStatus' => 'fail', 'healthAlertFailureThreshold' => 0])]);

        self::assertSame(200, $status);
        self::assertSame('ok', $body['status']);
    }

    public function testStaleProbeResultIsUnknownNotFailing(): void
    {
        $stale = $this->monitored('fail');
        $stale->assign(['healthAlertLastCheckedAt' => new \DateTimeImmutable('-2 hours')]);

        [$status, $body] = $this->health([$stale]);

        self::assertSame(200, $status);
        self::assertSame(1, $body['unknownProviders']);
    }

    public function testUnconfiguredWithoutActiveProviders(): void
    {
        [$status, $body] = $this->health([]);

        self::assertSame(200, $status);
        self::assertSame('unconfigured', $body['status']);
    }

    public function testInfrastructureWarningsAreReportedWithoutFailing(): void
    {
        $this->infrastructureWarnings = [InfrastructureInspector::WARNING_MULTI_NODE_WITHOUT_REDIS];

        [$status, $body] = $this->health([$this->provider([])]);

        self::assertSame(200, $status);
        self::assertSame(['warnings' => ['multi_node_without_redis']], $body['infrastructure']);
    }

    public function testConfiguredTokenIsRequired(): void
    {
        [$status] = $this->health([$this->provider([])], token: 's3cret', sentToken: null);
        self::assertSame(401, $status);

        [$status] = $this->health([$this->provider([])], token: 's3cret', sentToken: 's3cret');
        self::assertSame(200, $status);
    }

    public function testWithoutAConfiguredTokenOnlyTheStatusIsPublic(): void
    {
        [$status, $body] = $this->health([$this->provider([])], token: null, sentToken: null);

        // No counts, no infrastructure warnings for anonymous callers (R3-L36).
        self::assertSame(200, $status);
        self::assertSame(['status' => 'ok'], $body);
    }

    /**
     * @param list<Sw6OidcProviderEntity> $providers
     *
     * @return array{int, array<string, mixed>}
     */
    private function health(array $providers, ?string $token = 'monitor-token', ?string $sentToken = 'monitor-token'): array
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('search')->willReturnCallback(static fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
            Sw6OidcProviderDefinition::ENTITY_NAME,
            \count($providers),
            new Sw6OidcProviderCollection($providers),
            null,
            $criteria,
            $context,
        ));

        $infrastructure = $this->createStub(InfrastructureInspector::class);
        $infrastructure->method('inspect')->willReturn(['atomicStore' => 'database', 'nodesSeen' => 1, 'warnings' => $this->infrastructureWarnings]);

        $request = new Request();

        if ($sentToken !== null) {
            $request->headers->set(HealthCheckController::TOKEN_HEADER, $sentToken);
        }

        $response = (new HealthCheckController(
            $repository,
            new ProviderConfigInspector(new Sw6OidcEncryptor('app-secret')),
            $infrastructure,
            new ArrayAdapter(),
            null,
            $token,
        ))->health($request);

        self::assertSame('no-store, private', $response->headers->get('Cache-Control'));

        return [$response->getStatusCode(), json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR)];
    }

    private function monitored(string $lastStatus): Sw6OidcProviderEntity
    {
        return $this->provider([
            'healthAlertFailureThreshold' => 3,
            'healthAlertWebhookUrl' => 'https://hooks.example/x',
            'healthAlertLastStatus' => $lastStatus,
            'healthAlertLastCheckedAt' => new \DateTimeImmutable(),
        ]);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function provider(array $overrides): Sw6OidcProviderEntity
    {
        static $n = 0;
        $provider = new Sw6OidcProviderEntity();
        $provider->assign(array_merge([
            'id' => 'p' . ++$n,
            'authorizeEndpoint' => 'https://idp.example/authorize',
            'accessTokenEndpoint' => 'https://idp.example/token',
            'jwksEndpoint' => 'https://idp.example/jwks',
            'issuer' => 'https://idp.example',
            'clientId' => 'shop',
            'clientSecret' => 'secret',
        ], $overrides));

        return $provider;
    }
}
