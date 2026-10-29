<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Api;

use MartinKuhl\Sw6Oidc\Controller\Api\OidcAdminAuthController;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Oidc\LogoutContextStore;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\BuildsOidcAdminAuthController;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\PlatformRequest;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(OidcAdminAuthController::class)]
final class OidcAdminAuthControllerLogoutTest extends TestCase
{
    use BuildsOidcAdminAuthController;

    private const USER_ID = '0190a1b2c3d4e5f60718293a4b5c6d7e';

    private LogoutContextStore $store;

    protected function setUp(): void
    {
        $this->store = new LogoutContextStore(new InMemoryAtomicCache());
    }

    public function testReturnsIdpLogoutUrlForOidcAdmin(): void
    {
        $this->store->rememberForAdmin(self::USER_ID, 'a1000000000000000000000000000001');

        $body = $this->logout($this->provider());

        self::assertSame(['logoutUrl' => 'https://auth.example/logout?rd=' . rawurlencode('https://shop.example/admin/')], $body);
        self::assertNull($this->store->consumeForAdmin(self::USER_ID), 'logout context is single-use');
    }

    public function testRegistrySessionOfTheCurrentTokenWinsOverTheFallback(): void
    {
        $registry = SqliteSessionRegistry::create();
        $registry->register('a1000000000000000000000000000001', 'sub', 'sid-old', 'admin', self::USER_ID, 'jti-old', null, 'old-id-token');
        $current = $registry->register('a1000000000000000000000000000001', 'sub', 'sid-cur', 'admin', self::USER_ID, 'jti-current', null, 'current-id-token');
        $registry->register('a1000000000000000000000000000001', 'sub', 'sid-new', 'admin', self::USER_ID, 'jti-new', null, 'new-id-token');
        $this->store->rememberForAdmin(self::USER_ID, 'a1000000000000000000000000000001');

        $request = new Request();
        $request->attributes->set(PlatformRequest::ATTRIBUTE_OAUTH_ACCESS_TOKEN_ID, 'jti-current');
        $provider = $this->provider();
        $provider->setEndSessionEndpoint('https://idp.example/oidc/end-session');
        $provider->setLogoutStyle(Sw6OidcProviderDefinition::LOGOUT_STYLE_STANDARD);

        $body = $this->logout($provider, $registry, $request);

        parse_str((string) parse_url((string) $body['logoutUrl'], PHP_URL_QUERY), $query);
        self::assertSame('current-id-token', $query['id_token_hint']);
        self::assertNull($registry->get($current->id), 'the ended session leaves the registry');
        self::assertCount(2, SqliteSessionRegistry::sessionsOf($registry, 'admin', self::USER_ID));
    }

    public function testLoginSessionHandleFindsTheSessionAfterATokenRefresh(): void
    {
        $registry = SqliteSessionRegistry::create();
        $mine = $registry->register('a1000000000000000000000000000001', 'sub', 'sid-a', 'admin', self::USER_ID, 'jti-first', null, 'my-id-token');
        $other = $registry->register('a1000000000000000000000000000001', 'sub', 'sid-b', 'admin', self::USER_ID, 'jti-other', null, 'other-device-id-token');

        $request = new Request([], [OidcAdminAuthController::LOGIN_SESSION_FIELD => $mine->id]);
        $request->attributes->set(PlatformRequest::ATTRIBUTE_OAUTH_ACCESS_TOKEN_ID, 'jti-after-refresh');
        $provider = $this->provider();
        $provider->setEndSessionEndpoint('https://idp.example/oidc/end-session');
        $provider->setLogoutStyle(Sw6OidcProviderDefinition::LOGOUT_STYLE_STANDARD);

        $body = $this->logout($provider, $registry, $request);

        parse_str((string) parse_url((string) $body['logoutUrl'], PHP_URL_QUERY), $query);
        self::assertSame('my-id-token', $query['id_token_hint']);
        self::assertNull($registry->get($mine->id));
        self::assertNotNull($registry->get($other->id), 'the other device keeps its registry entry (N-M4)');
    }

    public function testWithoutExactMatchNothingIsRemovedAndNoOtherDevicesTokenIsUsed(): void
    {
        $registry = SqliteSessionRegistry::create();
        $registry->register('a1000000000000000000000000000001', 'sub', 'sid-old', 'admin', self::USER_ID, 'jti-old', null, 'old-id-token');
        $registry->register('a1000000000000000000000000000001', 'sub', 'sid-new', 'admin', self::USER_ID, 'jti-new', null, 'new-id-token');
        $this->store->rememberForAdmin(self::USER_ID, 'a1000000000000000000000000000001');
        $provider = $this->provider();
        $provider->setEndSessionEndpoint('https://idp.example/oidc/end-session');
        $provider->setLogoutStyle(Sw6OidcProviderDefinition::LOGOUT_STYLE_STANDARD);

        $body = $this->logout($provider, $registry, new Request());

        parse_str((string) parse_url((string) $body['logoutUrl'], PHP_URL_QUERY), $query);
        self::assertArrayNotHasKey('id_token_hint', $query);
        self::assertCount(2, SqliteSessionRegistry::sessionsOf($registry, 'admin', self::USER_ID));
    }

    public function testAnotherAdminsLoginSessionHandleIsIgnored(): void
    {
        $registry = SqliteSessionRegistry::create();
        $foreign = $registry->register('a1000000000000000000000000000001', 'sub', 'sid', 'admin', 'f0000000000000000000000000000001', 'jti', null, 'foreign-token');

        $body = $this->logout($this->provider(), $registry, new Request([], [OidcAdminAuthController::LOGIN_SESSION_FIELD => $foreign->id]));

        self::assertSame(['logoutUrl' => null], $body);
        self::assertNotNull($registry->get($foreign->id));
    }

    public function testReturnsNullWithoutLogoutContext(): void
    {
        self::assertSame(['logoutUrl' => null], $this->logout($this->provider()));
    }

    public function testReturnsNullForInactiveProvider(): void
    {
        $this->store->rememberForAdmin(self::USER_ID, 'a1000000000000000000000000000001');

        self::assertSame(['logoutUrl' => null], $this->logout(null));
    }

    /**
     * @return array<string, mixed>
     */
    private function logout(?Sw6OidcProviderEntity $provider, ?Sw6OidcSessionRegistry $registry = null, ?Request $request = null): array
    {
        $resolver = $this->createMock(ProviderResolver::class);
        if ($provider === null) {
            $resolver->method('getActiveById')->willThrowException(new ProviderNotFoundException('gone'));
        } else {
            $resolver->method('getActiveById')->willReturn($provider);
        }

        $controller = $this->buildAdminAuthController(array_filter([
            'providerResolver' => $resolver,
            'logoutContextStore' => $this->store,
            'sessionRegistry' => $registry,
        ]));

        $response = $controller->logout($request ?? new Request(), new Context(new AdminApiSource(self::USER_ID)));

        self::assertSame(200, $response->getStatusCode());

        return json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }

    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('a1000000000000000000000000000001');
        $provider->setClientId('shop-client');
        $provider->setEndSessionEndpoint('https://auth.example/logout');
        $provider->setLogoutStyle(Sw6OidcProviderDefinition::LOGOUT_STYLE_AUTHELIA_FORWARD_AUTH);

        return $provider;
    }
}
