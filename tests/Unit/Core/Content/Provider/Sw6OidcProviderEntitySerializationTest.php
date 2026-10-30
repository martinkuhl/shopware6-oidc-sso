<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Core\Content\Provider;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Sw6OidcProviderEntity::class)]
final class Sw6OidcProviderEntitySerializationTest extends TestCase
{
    public function testSecretsNeverReachASerialisation(): void
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('a1000000000000000000000000000001');
        $provider->setClientId('shop');
        $provider->setClientSecret('the-secret');
        $provider->setHealthAlertWebhookUrl('https://hooks.example/T000/secret');

        $json = (string) json_encode($provider);

        self::assertStringNotContainsString('the-secret', $json);
        self::assertStringNotContainsString('hooks.example', $json);
        self::assertStringContainsString('"clientId":"shop"', $json);
    }
}
