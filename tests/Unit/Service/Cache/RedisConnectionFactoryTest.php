<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Cache;

use MartinKuhl\Sw6Oidc\Service\Cache\RedisConnectionFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

#[CoversClass(RedisConnectionFactory::class)]
final class RedisConnectionFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{?string}>
     */
    public static function unusableDsns(): iterable
    {
        yield 'unset' => [null];
        yield 'empty' => [''];
        yield 'garbage' => ['not a dsn'];
        yield 'wrong scheme' => ['memcached://localhost:11211'];
    }

    #[DataProvider('unusableDsns')]
    public function testUnusableDsnYieldsNoConnection(?string $dsn): void
    {
        self::assertNull((new RedisConnectionFactory($dsn, new NullLogger()))->create());
    }

    public function testUnreachableHostYieldsNoConnection(): void
    {
        if (!\extension_loaded('redis')) {
            self::markTestSkipped('ext-redis not loaded');
        }

        // RFC 5737 TEST-NET address: never routable, connect() times out/fails.
        self::assertNull((new RedisConnectionFactory('redis://192.0.2.1:6379', new NullLogger()))->create());
    }

    public function testAConfiguredButUnusableDsnIsLoggedNotSilentlyIgnored(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning');

        $factory = new RedisConnectionFactory('not a dsn', $logger);

        self::assertTrue($factory->isConfigured());
        self::assertNull($factory->create());
    }

    public function testUnsetDsnIsNotConfiguredAndLogsNothing(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $factory = new RedisConnectionFactory(null, $logger);

        self::assertFalse($factory->isConfigured());
        self::assertNull($factory->create());
    }
}
