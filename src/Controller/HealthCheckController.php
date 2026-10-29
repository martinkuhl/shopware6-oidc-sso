<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Health\HealthAlertState;
use MartinKuhl\Sw6Oidc\Service\Health\InfrastructureInspector;
use MartinKuhl\Sw6Oidc\Service\Health\NodeHeartbeat;
use MartinKuhl\Sw6Oidc\Service\Health\ProviderConfigInspector;
use Psr\Cache\CacheItemPoolInterface;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Health endpoint for uptime monitors. Configuration completeness, the last
 * result of the scheduled reachability probe and setup warnings — it makes
 * **no outbound HTTP calls** itself, and reveals only counts and warning
 * codes, never provider names, ids, URLs or hostnames.
 *
 * - `ok` (200): every active provider is usable.
 * - `degraded` (200): some provider is incomplete or its monitored probe
 *   failed, but SSO still works through another one. A load balancer must not
 *   take the shop out of rotation for that.
 * - `down` (503): no active provider is usable.
 * - `unconfigured` (200): no active provider.
 *
 * Only providers that are actually monitored (threshold > 0 and a webhook)
 * count their probe result, and a result older than three check intervals is
 * reported as `unknown` instead of failing — turning alerting off must never
 * freeze a stale failure into the endpoint (N-M14). The result is cached for
 * 30 seconds; with SW6OIDC_HEALTH_TOKEN set, the token is required
 * (`X-Sw6oidc-Health-Token` header).
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class HealthCheckController extends AbstractController
{
    public const TOKEN_HEADER = 'X-Sw6oidc-Health-Token';

    private const CACHE_KEY = 'sw6oidc_health_result';
    private const CACHE_TTL_SECONDS = 30;
    /** HealthCheckAlertTask runs every 300 s. */
    private const STALE_AFTER_SECONDS = 900;

    /**
     * @param EntityRepository<Sw6OidcProviderCollection> $providerRepository
     */
    public function __construct(
        private readonly EntityRepository $providerRepository,
        private readonly ProviderConfigInspector $configInspector,
        private readonly InfrastructureInspector $infrastructureInspector,
        private readonly CacheItemPoolInterface $cache,
        private readonly ?NodeHeartbeat $nodeHeartbeat = null,
        #[\SensitiveParameter]
        private readonly ?string $healthToken = null,
    ) {
    }

    #[Route(
        path: '/sw6oidc/health',
        name: 'frontend.sw6oidc.health',
        defaults: ['_loginRequired' => false, '_httpCache' => false],
        methods: ['GET'],
    )]
    public function health(Request $request): JsonResponse
    {
        if (
            $this->healthToken !== null && $this->healthToken !== ''
            && !hash_equals($this->healthToken, (string) $request->headers->get(self::TOKEN_HEADER))
        ) {
            return $this->noStore(new JsonResponse(['error' => 'unauthorized'], Response::HTTP_UNAUTHORIZED));
        }

        // Every web node answers this probe, the message worker never does (R3-L32).
        $this->nodeHeartbeat?->record();

        $item = $this->cache->getItem(self::CACHE_KEY);

        if (!$item->isHit() || !\is_array($item->get())) {
            $item->set($this->evaluate());
            $item->expiresAfter(self::CACHE_TTL_SECONDS);
            $this->cache->save($item);
        }

        /** @var array{status: string} $result */
        $result = $item->get();
        $status = $result['status'] === 'down' ? Response::HTTP_SERVICE_UNAVAILABLE : Response::HTTP_OK;

        // Counts and infrastructure warnings only for a caller holding the
        // token: anonymous callers learn whether SSO works, nothing more (R3-L36).
        if ($this->healthToken === null || $this->healthToken === '') {
            return $this->noStore(new JsonResponse(['status' => $result['status']], $status));
        }

        return $this->noStore(new JsonResponse($result, $status));
    }

    /**
     * @return array<string, mixed>
     */
    private function evaluate(): array
    {
        $criteria = (new Criteria())->addFilter(new EqualsFilter('isActive', true));
        $active = 0;
        $usable = 0;
        $incomplete = 0;
        $unreachable = 0;
        $unknown = 0;

        foreach ($this->providerRepository->search($criteria, Context::createDefaultContext())->getEntities() as $provider) {
            if (!$provider instanceof Sw6OidcProviderEntity) {
                continue;
            }

            ++$active;
            $isIncomplete = $this->configInspector->problems($provider) !== [];
            $probe = $this->probeStatus($provider);

            $incomplete += (int) $isIncomplete;
            $unreachable += (int) ($probe === 'fail');
            $unknown += (int) ($probe === 'unknown');
            $usable += (int) (!$isIncomplete && $probe !== 'fail');
        }

        $status = match (true) {
            $active === 0 => 'unconfigured',
            $usable === 0 => 'down',
            $usable < $active => 'degraded',
            default => 'ok',
        };

        $infrastructure = $this->infrastructureInspector->inspect();

        return [
            'status' => $status,
            'activeProviders' => $active,
            'incompleteProviders' => $incomplete,
            'unreachableProviders' => $unreachable,
            'unknownProviders' => $unknown,
            'infrastructure' => ['warnings' => $infrastructure['warnings']],
        ];
    }

    /**
     * 'ok' | 'fail' | 'unknown' (stale result) | 'unmonitored'
     */
    private function probeStatus(Sw6OidcProviderEntity $provider): string
    {
        $monitored = $provider->getHealthAlertFailureThreshold() > 0
            && $provider->getHealthAlertWebhookUrl() !== null
            && $provider->getHealthAlertWebhookUrl() !== '';

        if (!$monitored) {
            return 'unmonitored';
        }

        $checkedAt = $provider->getHealthAlertLastCheckedAt();

        if (!$checkedAt instanceof \DateTimeInterface || $checkedAt->getTimestamp() < time() - self::STALE_AFTER_SECONDS) {
            return 'unknown';
        }

        return $provider->getHealthAlertLastStatus() === HealthAlertState::STATUS_FAIL ? 'fail' : 'ok';
    }

    private function noStore(JsonResponse $response): JsonResponse
    {
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
