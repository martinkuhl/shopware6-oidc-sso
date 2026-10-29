<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Logging;

use MartinKuhl\Sw6Oidc\Service\Logging\ConfigurableLevelHandler;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\System\SystemConfig\SystemConfigService;

#[CoversClass(ConfigurableLevelHandler::class)]
final class ConfigurableLevelHandlerTest extends TestCase
{
    public function testDefaultsToWarning(): void
    {
        $inner = new TestHandler();
        $handler = new ConfigurableLevelHandler($inner, $this->config(false));

        $handler->handle(self::record(Level::Info));
        $handler->handle(self::record(Level::Warning));

        self::assertFalse($inner->hasInfoRecords());
        self::assertTrue($inner->hasWarningRecords());
    }

    public function testDebugToggleLowersTheLevel(): void
    {
        $inner = new TestHandler();
        $handler = new ConfigurableLevelHandler($inner, $this->config(true));

        $handler->handle(self::record(Level::Debug));

        self::assertTrue($inner->hasDebugRecords());
    }

    public function testEnvBaseLevelAndInvalidNameFallback(): void
    {
        $inner = new TestHandler();
        (new ConfigurableLevelHandler($inner, $this->config(false), 'info'))->handle(self::record(Level::Info));
        self::assertTrue($inner->hasInfoRecords());

        $inner = new TestHandler();
        (new ConfigurableLevelHandler($inner, $this->config(false), 'nonsense'))->handle(self::record(Level::Info));
        self::assertFalse($inner->hasInfoRecords());
    }

    public function testConfigIsReadOncePerRequestAndResetRereadsIt(): void
    {
        $config = $this->createMock(SystemConfigService::class);
        $config->expects(self::exactly(2))->method('get')->willReturnOnConsecutiveCalls(false, true);

        $inner = new TestHandler();
        $handler = new ConfigurableLevelHandler($inner, $config);

        $handler->handle(self::record(Level::Debug));
        $handler->handle(self::record(Level::Debug));
        self::assertFalse($inner->hasDebugRecords());

        $handler->reset();
        $handler->handle(self::record(Level::Debug));
        self::assertTrue($inner->hasDebugRecords());
    }

    public function testConfigFailureFallsBackToTheBaseLevel(): void
    {
        $config = $this->createMock(SystemConfigService::class);
        $config->method('get')->willThrowException(new \RuntimeException('no database'));

        $inner = new TestHandler();
        $handler = new ConfigurableLevelHandler($inner, $config);
        $handler->handle(self::record(Level::Error));

        self::assertTrue($inner->hasErrorRecords());
    }

    private function config(bool $debug): SystemConfigService
    {
        $config = $this->createStub(SystemConfigService::class);
        $config->method('get')->willReturn($debug);

        return $config;
    }

    private static function record(Level $level): LogRecord
    {
        return new LogRecord(new \DateTimeImmutable(), 'sw6oidc', $level, 'message');
    }
}
