<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Migration;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Migration\Migration1790800010ReencryptSecrets;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Migration1790800010ReencryptSecrets::class)]
final class Migration1790800010ReencryptSecretsTest extends TestCase
{
    private const SECRET = 'migration-test-secret';

    private mixed $previousAppSecret;

    protected function setUp(): void
    {
        $this->previousAppSecret = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = self::SECRET;
    }

    protected function tearDown(): void
    {
        if ($this->previousAppSecret === null) {
            unset($_SERVER['APP_SECRET']);
        } else {
            $_SERVER['APP_SECRET'] = $this->previousAppSecret;
        }
    }

    public function testUpgradesDecryptableV1RowsPerField(): void
    {
        $rows = [
            'client_secret' => [
                ['id' => 'id-1', 'value' => self::v1('secret-1', self::SECRET)],
                ['id' => 'id-2', 'value' => self::v1('foreign', 'other-secret')],
            ],
            'health_alert_webhook_url' => [
                ['id' => 'id-1', 'value' => self::v1('https://hooks.example/T/1', self::SECRET)],
            ],
        ];

        $updates = [];
        $connection = $this->createMock(Connection::class);
        $connection->method('fetchAllAssociative')->willReturnCallback(static function (string $sql) use ($rows): array {
            return str_contains($sql, '`client_secret` AS') ? $rows['client_secret'] : $rows['health_alert_webhook_url'];
        });
        $connection->method('update')->willReturnCallback(static function (string $table, array $data, array $criteria) use (&$updates): int {
            $updates[] = [$data, $criteria];

            return 1;
        });

        (new Migration1790800010ReencryptSecrets())->update($connection);

        $encryptor = new Sw6OidcEncryptor(self::SECRET);

        self::assertCount(2, $updates, 'the foreign envelope is left alone');
        self::assertSame(['id' => 'id-1'], $updates[0][1]);
        self::assertStringStartsWith(Sw6OidcEncryptor::PREFIX, $updates[0][0]['client_secret']);
        self::assertSame('secret-1', $encryptor->decryptOrNull($updates[0][0]['client_secret'], 'sw6oidc_provider.client_secret'));
        self::assertSame('https://hooks.example/T/1', $encryptor->decryptOrNull($updates[1][0]['health_alert_webhook_url'], 'sw6oidc_provider.health_alert_webhook_url'));
    }

    public function testWithoutAppSecretDoesNothing(): void
    {
        $_SERVER['APP_SECRET'] = '';
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::never())->method('fetchAllAssociative');

        (new Migration1790800010ReencryptSecrets())->update($connection);
    }

    private static function v1(string $plaintext, string $appSecret): string
    {
        $key = sodium_crypto_generichash($appSecret . "\0sw6oidc/client_secret/v1", '', \SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return Sw6OidcEncryptor::LEGACY_PREFIX . base64_encode($nonce . sodium_crypto_secretbox($plaintext, $nonce, $key));
    }
}
