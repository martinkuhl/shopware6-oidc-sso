<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Api;

use MartinKuhl\Sw6Oidc\Controller\Api\OidcDiagnosticsController;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Health\InfrastructureInspector;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderConfigInspector;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderReachabilityChecker;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(OidcDiagnosticsController::class)]
final class OidcDiagnosticsControllerTest extends TestCase
{
    private ?Sw6OidcRateLimiter $rateLimiter = null;

    public function testReportsConfigProbeAndAlertingStateWithoutLeakingTheWebhook(): void
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign([
            'id' => 'p1',
            'authorizeEndpoint' => 'https://idp.example/authorize',
            'accessTokenEndpoint' => 'https://idp.example/token',
            'jwksEndpoint' => 'https://idp.example/jwks',
            'issuer' => null,
            'clientId' => 'shop',
            'clientSecret' => 'secret',
            'healthAlertFailureThreshold' => 3,
            'healthAlertWebhookUrl' => 'https://hooks.example/T0/B0/token',
            'healthAlertLastStatus' => 'fail',
            'healthAlertConsecutiveFailures' => 4,
        ]);

        $body = json_decode((string) $this->controller([$provider])->diagnostics('p1', new Request(), Context::createDefaultContext())->getContent(), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame(['issuer_missing'], $body['configProblems']);
        self::assertTrue($body['reachability']['ok']);
        self::assertSame(['enabled' => true, 'webhookConfigured' => true, 'threshold' => 3, 'lastStatus' => 'fail', 'consecutiveFailures' => 4], array_intersect_key($body['alerting'], array_flip(['enabled', 'webhookConfigured', 'threshold', 'lastStatus', 'consecutiveFailures'])));
        self::assertStringNotContainsString('hooks.example', (string) json_encode($body));
    }

    public function testUnknownProviderIs404(): void
    {
        self::assertSame(404, $this->controller([])->diagnostics('nope', new Request(), Context::createDefaultContext())->getStatusCode());
    }

    /**
     * @param list<Sw6OidcProviderEntity> $providers
     */
    private function controller(array $providers): OidcDiagnosticsController
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

        return new OidcDiagnosticsController(
            $repository,
            new ProviderConfigInspector(),
            new ProviderReachabilityChecker(new MockHttpClient(new MockResponse('{"keys":[{"kty":"RSA"}]}')), new SsrfUrlValidator(false, static fn (): array => ['93.184.215.14'])),
            $this->infrastructure(),
            $this->rateLimiter ?? new Sw6OidcRateLimiter(null, new ArrayAdapter(), 10, 60, 30),
        );
    }

    public function testTheLiveProbeIsRateLimited(): void
    {
        $this->rateLimiter = new Sw6OidcRateLimiter(null, new ArrayAdapter(), 10, 60, 1);
        $controller = $this->controller([]);

        self::assertSame(404, $controller->diagnostics('nope', new Request(), Context::createDefaultContext())->getStatusCode());
        self::assertSame(429, $controller->diagnostics('nope', new Request(), Context::createDefaultContext())->getStatusCode());
    }

    private function infrastructure(): InfrastructureInspector
    {
        $inspector = $this->createStub(InfrastructureInspector::class);
        $inspector->method('inspect')->willReturn(['atomicStore' => 'database', 'nodesSeen' => 2, 'warnings' => ['multi_node_without_redis']]);

        return $inspector;
    }
}
