<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Migration;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Migration\Migration1790685361EncryptProviderClientSecrets;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Migration1790685361EncryptProviderClientSecrets::class)]
final class Migration1790685361EncryptProviderClientSecretsTest extends TestCase
{
    private mixed $previousAppSecret;

    protected function setUp(): void
    {
        $this->previousAppSecret = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = 'migration-test-secret';
    }

    protected function tearDown(): void
    {
        if ($this->previousAppSecret === null) {
            unset($_SERVER['APP_SECRET']);
        } else {
            $_SERVER['APP_SECRET'] = $this->previousAppSecret;
        }
    }

    public function testEncryptsOnlyUnprefixedRows(): void
    {
        $updates = [];
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('executeStatement')->with(self::stringContains('VARCHAR(2048)'));
        $connection->expects(self::once())->method('fetchAllAssociative')
            ->with(self::stringContains('NOT LIKE'), ['prefix' => 'sw6oidc\_v%'])
            ->willReturn([['id' => 'id-1', 'client_secret' => 'plain-1']]);
        $connection->method('update')->willReturnCallback(static function (string $table, array $data, array $criteria) use (&$updates): int {
            $updates[] = [$table, $data, $criteria];

            return 1;
        });

        (new Migration1790685361EncryptProviderClientSecrets())->update($connection);

        self::assertCount(1, $updates);
        [$table, $data, $criteria] = $updates[0];
        self::assertSame('sw6oidc_provider', $table);
        self::assertSame(['id' => 'id-1'], $criteria);
        self::assertSame('plain-1', (new Sw6OidcEncryptor('migration-test-secret'))->decrypt($data['client_secret'], 'sw6oidc_provider.client_secret'));
    }

    public function testWithoutAppSecretOnlyWidensTheColumn(): void
    {
        $_SERVER['APP_SECRET'] = '';
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('executeStatement');
        $connection->expects(self::never())->method('fetchAllAssociative');

        (new Migration1790685361EncryptProviderClientSecrets())->update($connection);
    }
}
