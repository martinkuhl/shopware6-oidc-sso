<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Cache;

use MartinKuhl\Sw6Oidc\Service\Cache\DatabaseAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Cache\RedisAtomicCache;
use MartinKuhl\Sw6Oidc\Service\Cache\RedisConnectionFactory;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Constraint\Callback;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

#[CoversClass(RedisAtomicCache::class)]
#[RequiresPhpExtension('redis')]
final class RedisAtomicCacheTest extends TestCase
{
    public function testWithoutConnectionEverythingGoesToFallback(): void
    {
        $fallback = new InMemoryAtomicCache();
        $cache = new RedisAtomicCache(new RedisConnectionFactory(null, new NullLogger()), $fallback, new NullLogger(), self::encryptor());

        $cache->save('k', 'v', 60);

        self::assertSame(['k' => 'v'], $fallback->items);
        self::assertSame('v', $cache->getAndDelete('k'));
        self::assertNull($cache->getAndDelete('k'));
    }

    public function testAlwaysUsesTheLuaScriptSoOldRedisServersWork(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->expects(self::never())->method('getdel');
        $redis->expects(self::once())->method('eval')
            ->with(self::stringContains("redis.call('GET'"), self::callback(static fn (array $keys): bool => str_starts_with($keys[0], 'sw6oidc:')), 1)
            ->willReturn('v');

        $cache = new RedisAtomicCache($this->factoryReturning($redis), new InMemoryAtomicCache(), new NullLogger(), self::encryptor());

        self::assertSame('v', $cache->getAndDelete('k'));
        self::assertSame(RedisAtomicCache::BACKEND_REDIS, $cache->backend());
    }

    public function testAddIfAbsentUsesSetNx(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->expects(self::exactly(2))->method('set')
            ->with(self::stringStartsWith('sw6oidc:'), self::sealedValue('1'), ['nx', 'ex' => 60])
            ->willReturnOnConsecutiveCalls(true, false);

        $cache = new RedisAtomicCache($this->factoryReturning($redis), new InMemoryAtomicCache(), new NullLogger(), self::encryptor());

        self::assertTrue($cache->addIfAbsent('jti', '1', 60));
        self::assertFalse($cache->addIfAbsent('jti', '1', 60));
    }

    public function testWithoutRedisTheBackendIsTheDatabase(): void
    {
        $cache = new RedisAtomicCache(new RedisConnectionFactory(null, new NullLogger()), new InMemoryAtomicCache(), new NullLogger(), self::encryptor());

        self::assertSame(RedisAtomicCache::BACKEND_DATABASE, $cache->backend());
        self::assertTrue($cache->addIfAbsent('k', 'v', 60));
        self::assertFalse($cache->addIfAbsent('k', 'v', 60));
    }

    public function testUsesRedisWhenConnected(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->expects(self::once())->method('setex')->with(self::stringStartsWith('sw6oidc:'), 60, self::sealedValue('v'))->willReturnCallback(static function (string $key, int $ttl, string $value) use (&$stored): bool {
            $stored = $value;

            return true;
        });
        $stored = null;
        $redis->expects(self::once())->method('eval')->willReturnCallback(static function () use (&$stored): ?string {
            return $stored;
        });
        $fallback = new InMemoryAtomicCache();

        $cache = new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor());
        $cache->save('k', 'v', 60);

        self::assertSame('v', $cache->getAndDelete('k'));
        self::assertSame([], $fallback->items);
    }

    public function testSaveErrorFallsBackAndIsStillConsumable(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('setex')->willThrowException(new \RedisException('gone'));
        $redis->method('eval')->willReturn(false);
        $fallback = new InMemoryAtomicCache();

        $cache = new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor());
        $cache->save('k', 'v', 60);

        self::assertSame('v', $cache->getAndDelete('k'));
        self::assertNull($cache->getAndDelete('k'));
    }

    public function testReadErrorFallsBack(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('eval')->willThrowException(new \RedisException('gone'));
        $fallback = new InMemoryAtomicCache();
        $fallback->save('k', 'v', 60);

        $cache = new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor());

        self::assertSame('v', $cache->getAndDelete('k'));
    }

    /**
     * R3-M18: phpredis returns false for error replies (READONLY after a
     * failover, OOM). That must not read as "already seen" — a valid
     * back-channel logout would be dropped as a replay.
     */
    public function testAnErrorReplyOnSetNxIsNotAReplay(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('set')->willReturn(false);
        $redis->method('getLastError')->willReturn("READONLY You can't write against a read only replica.");
        $redis->expects(self::once())->method('clearLastError');
        $fallback = new InMemoryAtomicCache();

        $cache = new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor());

        self::assertTrue($cache->addIfAbsent('jti', '1', 60));
        self::assertSame(['jti' => '1'], $fallback->items);
    }

    public function testAnErrorReplyOnSaveFallsBack(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('setex')->willReturn(false);
        $redis->method('getLastError')->willReturn('OOM command not allowed');
        $fallback = new InMemoryAtomicCache();

        (new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor()))->save('k', 'v', 60);

        self::assertSame(['k' => 'v'], $fallback->items);
    }

    public function testAnErrorReplyOnReadFallsBack(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('eval')->willReturn(false);
        $redis->method('getLastError')->willReturn('MISCONF');
        $fallback = new InMemoryAtomicCache();
        $fallback->save('k', 'v', 60);

        self::assertSame('v', (new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor()))->getAndDelete('k'));
    }

    public function testDeleteRemovesFromBothStores(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->expects(self::once())->method('del')->with(self::stringStartsWith('sw6oidc:'));
        $fallback = new InMemoryAtomicCache();
        $fallback->save('k', 'v', 60);

        (new RedisAtomicCache($this->factoryReturning($redis), $fallback, new NullLogger(), self::encryptor()))->delete('k');

        self::assertSame([], $fallback->items);
    }

    public function testConnectsOnlyOnce(): void
    {
        $factory = $this->createMock(RedisConnectionFactory::class);
        $factory->expects(self::once())->method('create')->willReturn(null);

        $cache = new RedisAtomicCache($factory, new InMemoryAtomicCache(), new NullLogger(), self::encryptor());
        $cache->save('a', '1', 60);
        $cache->getAndDelete('a');
        $cache->getAndDelete('b');
    }

    private function factoryReturning(\Redis $redis): RedisConnectionFactory
    {
        $factory = $this->createMock(RedisConnectionFactory::class);
        $factory->method('create')->willReturn($redis);

        return $factory;
    }

    public function testValuesAreEncryptedInRedis(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->expects(self::once())->method('setex')
            ->with(self::anything(), 60, self::logicalNot(self::stringContains('pkce-verifier')))
            ->willReturn(true);

        // R3-L35: a Redis dump must not reveal verifiers or user ids.
        (new RedisAtomicCache($this->factoryReturning($redis), new InMemoryAtomicCache(), new NullLogger(), self::encryptor()))->save('k', 'pkce-verifier', 60);
    }

    public function testPlaintextFromBeforeTheUpdateIsStillRead(): void
    {
        $redis = $this->createMock(\Redis::class);
        $redis->method('eval')->willReturn('legacy-plain');

        self::assertSame('legacy-plain', (new RedisAtomicCache($this->factoryReturning($redis), new InMemoryAtomicCache(), new NullLogger(), self::encryptor()))->getAndDelete('k'));
    }

    private static function encryptor(): Sw6OidcEncryptor
    {
        return new Sw6OidcEncryptor('test-app-secret');
    }

    private static function sealedValue(string $plaintext): Callback
    {
        return self::callback(static fn (string $value): bool => self::encryptor()->decryptOrNull($value, DatabaseAtomicCache::VALUE_PURPOSE) === $plaintext && $value !== $plaintext);
    }
}
