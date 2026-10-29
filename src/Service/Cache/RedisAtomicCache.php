<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Cache;

use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Psr\Log\LoggerInterface;

/**
 * The AtomicCacheInterface implementation the plugin always wires. Selects its
 * backend at runtime rather than at container-compile time (a compile-time
 * switch would be frozen into Shopware's cached container, so changing
 * SW6OIDC_REDIS_DSN would silently do nothing until the next cache:clear):
 *
 *  - SW6OIDC_REDIS_DSN set, ext-redis loaded, connection OK: Redis. Reads use
 *    a GET+DEL Lua script, which is atomic on every Redis version (GETDEL
 *    needs a 6.2+ *server*; checking the client's method list says nothing
 *    about that), writes use SET … NX EX for addIfAbsent().
 *  - Otherwise, and per call whenever Redis errors: the database store
 *    (DatabaseAtomicCache), which is atomic and shared by all app servers too.
 *
 * A value written to the database because Redis failed on save() is still
 * found by getAndDelete(), which consults the database on a Redis miss.
 *
 * phpredis answers server error replies (OOM under `noeviction`, READONLY
 * after a failover, MISCONF) with `false` instead of an exception. `false`
 * from SET NX means "already present" only when Redis reported no error;
 * anything else is an error and falls back to the database (R3-M18) — a
 * back-channel logout must never be mistaken for a replay. This Redis must
 * not evict keys (`maxmemory-policy noeviction`).
 */
class RedisAtomicCache implements AtomicCacheInterface
{
    public const BACKEND_REDIS = 'redis';
    public const BACKEND_DATABASE = 'database';

    private const GET_AND_DELETE_LUA = <<<'LUA'
        local value = redis.call('GET', KEYS[1])
        if value then
            redis.call('DEL', KEYS[1])
        end
        return value
        LUA;

    private ?\Redis $redis = null;

    private bool $resolved = false;

    public function __construct(
        private readonly RedisConnectionFactory $connectionFactory,
        private readonly AtomicCacheInterface $fallback,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcEncryptor $encryptor,
    ) {
    }

    /**
     * Which store this process uses ('redis' or 'database').
     */
    public function backend(): string
    {
        return $this->redis() instanceof \Redis ? self::BACKEND_REDIS : self::BACKEND_DATABASE;
    }

    public function save(string $key, string $value, int $ttlSeconds): void
    {
        $redis = $this->redis();

        if (!$redis instanceof \Redis) {
            $this->fallback->save($key, $value, $ttlSeconds);

            return;
        }

        try {
            if ($redis->setex($this->prefixedKey($key), max(1, $ttlSeconds), $this->seal($value)) !== true) {
                throw new \RuntimeException($this->takeLastError($redis) ?? 'SETEX failed');
            }
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: Redis save failed; using the database store for this token.', [
                'exceptionClass' => $exception::class,
            ]);
            $this->fallback->save($key, $value, $ttlSeconds);
        }
    }

    public function getAndDelete(string $key): ?string
    {
        $redis = $this->redis();

        if (!$redis instanceof \Redis) {
            return $this->fallback->getAndDelete($key);
        }

        try {
            $value = $redis->eval(self::GET_AND_DELETE_LUA, [$this->prefixedKey($key)], 1);

            // A miss is `false` too; only a reported error is one.
            if ($value === false && ($error = $this->takeLastError($redis)) !== null) {
                throw new \RuntimeException($error);
            }
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: Redis getAndDelete failed; trying the database store.', [
                'exceptionClass' => $exception::class,
            ]);

            return $this->fallback->getAndDelete($key);
        }

        if (\is_string($value)) {
            // Values written before encryption (at most one TTL ago) pass through.
            return $this->encryptor->decryptOrNull($value, DatabaseAtomicCache::VALUE_PURPOSE);
        }

        // Miss: the token may have been written to the database by a save()
        // that hit a Redis error.
        return $this->fallback->getAndDelete($key);
    }

    public function addIfAbsent(string $key, string $value, int $ttlSeconds): bool
    {
        $redis = $this->redis();

        if (!$redis instanceof \Redis) {
            return $this->fallback->addIfAbsent($key, $value, $ttlSeconds);
        }

        try {
            $result = $redis->set($this->prefixedKey($key), $this->seal($value), ['nx', 'ex' => max(1, $ttlSeconds)]);

            if ($result === true) {
                return true;
            }

            $error = $this->takeLastError($redis);

            if ($error === null) {
                // NX refused: the key exists.
                return false;
            }

            throw new \RuntimeException($error);
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: Redis addIfAbsent failed; using the database store.', [
                'exceptionClass' => $exception::class,
            ]);

            return $this->fallback->addIfAbsent($key, $value, $ttlSeconds);
        }
    }

    /**
     * The server's `maxmemory-policy`, or null when Redis isn't in use or
     * doesn't allow CONFIG GET (managed services often don't).
     */
    public function evictionPolicy(): ?string
    {
        $redis = $this->redis();

        if (!$redis instanceof \Redis) {
            return null;
        }

        try {
            $policy = $this->policyFrom($redis->config('GET', 'maxmemory-policy'));
        } catch (\Throwable) {
            return null;
        }

        $this->takeLastError($redis);

        return $policy;
    }

    /**
     * phpredis returns ['maxmemory-policy' => value] (its stubs say string).
     */
    private function policyFrom(mixed $config): ?string
    {
        return \is_array($config) && \is_string($config['maxmemory-policy'] ?? null) ? $config['maxmemory-policy'] : null;
    }

    public function delete(string $key): void
    {
        $redis = $this->redis();

        if ($redis instanceof \Redis) {
            try {
                $redis->del($this->prefixedKey($key));
            } catch (\Throwable $exception) {
                $this->logger->warning('sw6oidc: Redis delete failed.', ['exceptionClass' => $exception::class]);
            }
        }

        // The value may have been stored there during a Redis error.
        $this->fallback->delete($key);
    }

    /**
     * PKCE verifiers, nonces and user ids are encrypted like in the database
     * store, so a Redis dump or a shared instance reveals nothing (R3-L35).
     */
    private function seal(string $value): string
    {
        return $this->encryptor->encrypt($value, DatabaseAtomicCache::VALUE_PURPOSE);
    }

    /**
     * The error of the last command, cleared so the next one starts clean.
     */
    private function takeLastError(\Redis $redis): ?string
    {
        $error = $redis->getLastError();

        if ($error === null) {
            return null;
        }

        $redis->clearLastError();

        return $error;
    }

    private function redis(): ?\Redis
    {
        if (!$this->resolved) {
            $this->resolved = true;
            $this->redis = $this->connectionFactory->create();
        }

        return $this->redis;
    }

    private function prefixedKey(string $key): string
    {
        return 'sw6oidc:' . hash('sha256', $key);
    }
}
