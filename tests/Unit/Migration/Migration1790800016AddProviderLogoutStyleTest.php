<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Migration;

use MartinKuhl\Sw6Oidc\Migration\Migration1790800016AddProviderLogoutStyle;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * R3-M3: existing Authelia providers keep the portal logout; the IdPs the
 * old URL guess misread get the standard logout.
 */
#[CoversClass(Migration1790800016AddProviderLogoutStyle::class)]
final class Migration1790800016AddProviderLogoutStyleTest extends TestCase
{
    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function endpoints(): iterable
    {
        yield 'Authelia portal' => ['https://auth.example.com/logout', true];
        yield 'Authelia portal in a sub path' => ['https://example.com/authelia/logout', true];
        yield 'Keycloak' => ['https://kc.example.com/realms/shop/protocol/openid-connect/logout', false];
        yield 'Auth0' => ['https://tenant.eu.auth0.com/v2/logout', false];
        yield 'Okta' => ['https://org.okta.com/oauth2/default/v1/logout', false];
        yield 'Okta org server' => ['https://org.okta.com/oauth2/v1/logout', false];
        yield 'Entra ID' => ['https://login.microsoftonline.com/tenant/oauth2/v2.0/logout', false];
        yield 'Authelia OIDC end session' => ['https://auth.example.com/api/oidc/end-session', false];
        yield 'Zitadel' => ['https://zitadel.example.com/oidc/v1/end_session', false];
    }

    #[DataProvider('endpoints')]
    public function testClassification(string $endpoint, bool $authelia): void
    {
        self::assertSame($authelia, Migration1790800016AddProviderLogoutStyle::wasTreatedAsAuthelia($endpoint));
    }
}
