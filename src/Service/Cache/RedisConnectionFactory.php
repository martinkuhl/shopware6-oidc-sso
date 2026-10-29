<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Cache;

use Psr\Log\LoggerInterface;

/**
 * Opens the dedicated phpredis connection for one-time tokens, configured
 * via `SW6OIDC_REDIS_DSN` (redis://[[user]:password@]host:port[/db], or
 * rediss:// for TLS). Unset is a fully supported default: tokens then live
 * in the database (DatabaseAtomicCache).
 *
 * A DSN that is set but unusable (ext-redis missing, unparsable, connection,
 * AUTH or SELECT failing) is logged as a warning — silently degrading would
 * hide a broken setup. A persistent connection with connect and read
 * timeouts is used, and a failed connect is remembered for 30 seconds (in
 * APCu when available), so an outage doesn't stall every request.
 */
class RedisConnectionFactory
{
    private const CONNECT_TIMEOUT_SECONDS = 1.5;
    private const READ_TIMEOUT_SECONDS = 1.5;
    private const DOWN_MARKER_KEY = 'sw6oidc_redis_down';
    private const DOWN_MARKER_TTL_SECONDS = 30;

    private static int $processDownAt = 0;

    public function __construct(
        #[\SensitiveParameter]
        private readonly ?string $dsn,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function isConfigured(): bool
    {
        return $this->dsn !== null && $this->dsn !== '';
    }

    public function create(): ?\Redis
    {
        if (!$this->isConfigured()) {
            return null;
        }

        \assert(\is_string($this->dsn));

        if (!\extension_loaded('redis')) {
            $this->logger->warning('sw6oidc: SW6OIDC_REDIS_DSN is set but the redis PHP extension is not loaded; using the database store for one-time tokens.');

            return null;
        }

        $parts = parse_url($this->dsn);

        if ($parts === false || !isset($parts['host']) || !\in_array($parts['scheme'] ?? '', ['redis', 'rediss'], true)) {
            $this->logger->warning('sw6oidc: SW6OIDC_REDIS_DSN is set but could not be parsed; using the database store for one-time tokens.');

            return null;
        }

        if ($this->recentlyDown()) {
            return null;
        }

        try {
            $redis = new \Redis();
            $host = ($parts['scheme'] === 'rediss' ? 'tls://' : '') . $parts['host'];
            $database = isset($parts['path']) ? (int) ltrim($parts['path'], '/') : 0;

            if (!$redis->pconnect($host, $parts['port'] ?? 6379, self::CONNECT_TIMEOUT_SECONDS, 'sw6oidc-' . $database)) {
                throw new \RuntimeException('connect failed');
            }

            $redis->setOption(\Redis::OPT_READ_TIMEOUT, self::READ_TIMEOUT_SECONDS);

            if (isset($parts['pass'])) {
                $credentials = isset($parts['user']) && $parts['user'] !== ''
                    ? [rawurldecode($parts['user']), rawurldecode($parts['pass'])]
                    : rawurldecode($parts['pass']);

                if ($redis->auth($credentials) !== true) {
                    throw new \RuntimeException('AUTH rejected');
                }
            }

            if ($database > 0 && $redis->select($database) !== true) {
                throw new \RuntimeException('SELECT failed');
            }

            return $redis;
        } catch (\Throwable $exception) {
            $this->markDown();
            $this->logger->warning('sw6oidc: could not use the Redis connection from SW6OIDC_REDIS_DSN; using the database store for one-time tokens.', [
                'exceptionClass' => $exception::class,
                'reason' => $exception instanceof \RuntimeException ? $exception->getMessage() : null,
            ]);

            return null;
        }
    }

    /**
     * Whether a connect failed within the last 30 s, on this node: APCu when
     * available, else this process plus a marker file shared by the node's
     * processes — without one, every request of an outage would wait for
     * the connect timeout (R3-L39).
     */
    private function recentlyDown(): bool
    {
        if (\function_exists('apcu_enabled') && apcu_enabled()) {
            return apcu_fetch(self::DOWN_MARKER_KEY) === true;
        }

        if (time() - self::$processDownAt < self::DOWN_MARKER_TTL_SECONDS) {
            return true;
        }

        $markedAt = @filemtime($this->markerFile());

        return \is_int($markedAt) && time() - $markedAt < self::DOWN_MARKER_TTL_SECONDS;
    }

    private function markDown(): void
    {
        if (\function_exists('apcu_enabled') && apcu_enabled()) {
            apcu_store(self::DOWN_MARKER_KEY, true, self::DOWN_MARKER_TTL_SECONDS);

            return;
        }

        self::$processDownAt = time();
        @touch($this->markerFile());
    }

    private function markerFile(): string
    {
        // Per DSN, so two shops on one host don't share an outage marker.
        return sys_get_temp_dir() . '/' . self::DOWN_MARKER_KEY . '_' . substr(hash('sha256', (string) $this->dsn), 0, 16);
    }
}
