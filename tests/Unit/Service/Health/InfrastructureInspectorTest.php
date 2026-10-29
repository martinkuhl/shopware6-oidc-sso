<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Health;

use MartinKuhl\Sw6Oidc\Service\Cache\RedisAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Cache\RedisConnectionFactory;
use MartinKuhl\Sw6Oidc\Service\Health\InfrastructureInspector;
use MartinKuhl\Sw6Oidc\Service\Health\NodeHeartbeat;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(InfrastructureInspector::class)]
final class InfrastructureInspectorTest extends TestCase
{
    /**
     * @return iterable<string, array{bool, string, int, list<string>}>
     */
    public static function setups(): iterable
    {
        yield 'single node, no redis' => [false, 'database', 1, []];
        yield 'single node, redis' => [true, 'redis', 1, []];
        yield 'dsn set but unusable' => [true, 'database', 1, [InfrastructureInspector::WARNING_REDIS_DSN_UNUSABLE]];
        yield 'multi node without redis' => [false, 'database', 3, [InfrastructureInspector::WARNING_MULTI_NODE_WITHOUT_REDIS]];
        yield 'multi node, broken redis' => [true, 'database', 2, [InfrastructureInspector::WARNING_REDIS_DSN_UNUSABLE, InfrastructureInspector::WARNING_MULTI_NODE_WITHOUT_REDIS]];
        yield 'multi node with redis' => [true, 'redis', 4, []];
    }

    /**
     * @param list<string> $expectedWarnings
     */
    #[DataProvider('setups')]
    public function testWarnings(bool $dsnConfigured, string $backend, int $nodes, array $expectedWarnings): void
    {
        $cache = $this->createStub(RedisAtomicCache::class);
        $cache->method('backend')->willReturn($backend);
        $factory = $this->createStub(RedisConnectionFactory::class);
        $factory->method('isConfigured')->willReturn($dsnConfigured);
        $heartbeat = $this->createStub(NodeHeartbeat::class);
        $heartbeat->method('recentNodeCount')->willReturn($nodes);

        self::assertSame(
            ['atomicStore' => $backend, 'nodesSeen' => $nodes, 'warnings' => $expectedWarnings],
            (new InfrastructureInspector($cache, $factory, $heartbeat))->inspect(),
        );
    }
}
