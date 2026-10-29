<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Integration;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Cache\DatabaseAtomicCache;
use MartinKuhl\Sw6Oidc\Tests\Integration\Support\Sw6OidcIntegrationTestCase;

/**
 * The database one-time-token store on the real MySQL schema (its locking
 * read isn't portable to the unit tests' SQLite).
 */
final class DatabaseAtomicCacheTest extends Sw6OidcIntegrationTestCase
{
    public function testValueIsConsumedExactlyOnce(): void
    {
        $cache = $this->cache();
        $cache->save('state-1', 'flow', 60);

        self::assertSame('flow', $cache->getAndDelete('state-1'));
        self::assertNull($cache->getAndDelete('state-1'));
    }

    public function testKeysAreHashedAndValuesEncrypted(): void
    {
        $this->cache()->save('state-secret-key', 'pkce-verifier-secret', 60);

        $row = $this->connection()->fetchAssociative('SELECT * FROM sw6oidc_one_time_token WHERE key_hash = :hash', ['hash' => hash('sha256', 'state-secret-key')]);

        self::assertIsArray($row);
        self::assertStringNotContainsString('pkce-verifier-secret', (string) $row['value']);
    }

    public function testExpiredValuesAreNeverReturnedAndPruned(): void
    {
        $cache = $this->cache();
        $cache->save('old', 'v', 60);
        $this->connection()->executeStatement('UPDATE sw6oidc_one_time_token SET expires_at = :past', ['past' => '2000-01-01 00:00:00.000']);

        self::assertNull($cache->getAndDelete('old'));

        $cache->save('old-2', 'v', 60);
        $this->connection()->executeStatement('UPDATE sw6oidc_one_time_token SET expires_at = :past', ['past' => '2000-01-01 00:00:00.000']);
        self::assertSame(1, $cache->prune());
    }

    public function testAddIfAbsentIsSetIfNotExists(): void
    {
        $cache = $this->cache();

        self::assertTrue($cache->addIfAbsent('jti-1', '1', 60));
        self::assertFalse($cache->addIfAbsent('jti-1', '1', 60));

        $this->connection()->executeStatement('UPDATE sw6oidc_one_time_token SET expires_at = :past', ['past' => '2000-01-01 00:00:00.000']);
        self::assertTrue($cache->addIfAbsent('jti-1', '1', 60), 'an expired marker does not block');
    }

    private function cache(): DatabaseAtomicCache
    {
        $cache = static::getContainer()->get(DatabaseAtomicCache::class);
        \assert($cache instanceof DatabaseAtomicCache);

        return $cache;
    }

    private function connection(): Connection
    {
        $connection = static::getContainer()->get(Connection::class);
        \assert($connection instanceof Connection);

        return $connection;
    }
}
