<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use MartinKuhl\Sw6Oidc\Service\Cache\RedisAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Cache\RedisConnectionFactory;

/**
 * Setup problems that documentation alone doesn't surface, reported by the
 * health endpoint and the provider diagnostics:
 *
 *  - `redis_dsn_unusable`: SW6OIDC_REDIS_DSN is set, but one-time tokens are
 *    not stored in Redis (extension missing, unreachable, AUTH failing).
 *  - `multi_node_without_redis`: more than one app server handled the plugin
 *    in the last 15 minutes and Redis isn't in use. One-time tokens stay
 *    correct (they live in the database), but the rate limiter and the JWKS
 *    cache are per node unless Shopware's cache pools are shared.
 *  - `redis_may_evict`: the Redis used for one-time tokens may evict keys
 *    (`maxmemory-policy` other than `noeviction`): evicted flow state fails
 *    logins, an evicted replay marker lets a logout token be replayed
 *    (R3-M18).
 *
 * Warnings never make the health check fail: SSO keeps working.
 */
class InfrastructureInspector
{
    public const WARNING_REDIS_DSN_UNUSABLE = 'redis_dsn_unusable';
    public const WARNING_MULTI_NODE_WITHOUT_REDIS = 'multi_node_without_redis';
    public const WARNING_REDIS_MAY_EVICT = 'redis_may_evict';

    public function __construct(
        private readonly RedisAtomicCache $atomicCache,
        private readonly RedisConnectionFactory $redisConnectionFactory,
        private readonly NodeHeartbeat $nodeHeartbeat,
    ) {
    }

    /**
     * @return array{atomicStore: string, nodesSeen: int, warnings: list<string>}
     */
    public function inspect(): array
    {
        $backend = $this->atomicCache->backend();
        $nodes = $this->nodeHeartbeat->recentNodeCount();
        $warnings = [];

        if ($this->redisConnectionFactory->isConfigured() && $backend !== RedisAtomicCache::BACKEND_REDIS) {
            $warnings[] = self::WARNING_REDIS_DSN_UNUSABLE;
        }

        if ($nodes > 1 && $backend !== RedisAtomicCache::BACKEND_REDIS) {
            $warnings[] = self::WARNING_MULTI_NODE_WITHOUT_REDIS;
        }

        $evictionPolicy = $backend === RedisAtomicCache::BACKEND_REDIS ? $this->atomicCache->evictionPolicy() : null;

        if ($evictionPolicy !== null && $evictionPolicy !== 'noeviction') {
            $warnings[] = self::WARNING_REDIS_MAY_EVICT;
        }

        return ['atomicStore' => $backend, 'nodesSeen' => $nodes, 'warnings' => $warnings];
    }
}
