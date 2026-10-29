<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Support;

use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;

final class InMemoryAtomicCache implements AtomicCacheInterface
{
    /** @var array<string, string> */
    public array $items = [];

    public function save(string $key, string $value, int $ttlSeconds): void
    {
        $this->items[$key] = $value;
    }

    public function getAndDelete(string $key): ?string
    {
        $value = $this->items[$key] ?? null;
        unset($this->items[$key]);

        return $value;
    }

    public function delete(string $key): void
    {
        unset($this->items[$key]);
    }

    public function addIfAbsent(string $key, string $value, int $ttlSeconds): bool
    {
        if (\array_key_exists($key, $this->items)) {
            return false;
        }

        $this->items[$key] = $value;

        return true;
    }
}
