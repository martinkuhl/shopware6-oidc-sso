<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Logging;

use Monolog\Handler\HandlerInterface;
use Monolog\Level;
use Monolog\LogRecord;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Symfony\Contracts\Service\ResetInterface;

/**
 * The sw6oidc channel's level: SW6OIDC_LOG_LEVEL (default `warning`), or
 * `debug` while the plugin setting "Enable debug logging" is on — so the
 * setting does what it says, without a deploy, and production isn't flooded
 * with claim-level detail by default (Future Improvement 1, H9).
 *
 * The setting is read lazily, once per request (reset between requests in
 * long-running workers).
 */
final class ConfigurableLevelHandler implements HandlerInterface, ResetInterface
{
    private const CONFIG_KEY = 'Sw6Oidc.config.debugLoggingEnabled';

    private readonly Level $baseLevel;

    private ?Level $effectiveLevel = null;

    private bool $resolving = false;

    public function __construct(
        private readonly HandlerInterface $inner,
        private readonly SystemConfigService $systemConfigService,
        string $baseLevel = 'warning',
    ) {
        $this->baseLevel = match (strtolower(trim($baseLevel))) {
            'debug' => Level::Debug,
            'info' => Level::Info,
            'notice' => Level::Notice,
            'error' => Level::Error,
            'critical' => Level::Critical,
            'alert' => Level::Alert,
            'emergency' => Level::Emergency,
            default => Level::Warning,
        };
    }

    public function isHandling(LogRecord $record): bool
    {
        return $record->level->value >= $this->effectiveLevel()->value;
    }

    public function handle(LogRecord $record): bool
    {
        if (!$this->isHandling($record)) {
            return false;
        }

        return $this->inner->handle($record);
    }

    public function handleBatch(array $records): void
    {
        $this->inner->handleBatch(array_values(array_filter($records, $this->isHandling(...))));
    }

    public function close(): void
    {
        $this->inner->close();
    }

    public function reset(): void
    {
        $this->effectiveLevel = null;

        if ($this->inner instanceof ResetInterface) {
            $this->inner->reset();
        }
    }

    private function effectiveLevel(): Level
    {
        if ($this->effectiveLevel instanceof \Monolog\Level) {
            return $this->effectiveLevel;
        }

        // Reading the config may itself log (or fail before the DB is up): fall back to the base level.
        if ($this->resolving) {
            return $this->baseLevel;
        }

        $this->resolving = true;

        try {
            $debug = (bool) $this->systemConfigService->get(self::CONFIG_KEY);
        } catch (\Throwable) {
            $debug = false;
        } finally {
            $this->resolving = false;
        }

        return $this->effectiveLevel = $debug ? Level::Debug : $this->baseLevel;
    }
}
