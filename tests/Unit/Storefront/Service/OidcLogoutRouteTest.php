<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Storefront\Service;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use MartinKuhl\Sw6Oidc\Service\Oidc\RpInitiatedLogoutService;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Storefront\Service\OidcLogoutRoute;
use MartinKuhl\Sw6Oidc\Storefront\Service\PendingLogoutRedirect;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[CoversClass(OidcLogoutRoute::class)]
final class OidcLogoutRouteTest extends TestCase
{
    private const PRE_LOGOUT_TOKEN = 'pre-logout-token';
    private const LOGIN_URL = 'https://shop.example/account/login';
    private const CUSTOMER_ID = 'c1000000000000000000000000000001';

    private PendingLogoutRedirect $pending;

    private Sw6OidcSessionRegistry $registry;

    protected function setUp(): void
    {
        $this->pending = new PendingLogoutRedirect();
        $this->registry = SqliteSessionRegistry::create();
    }

    public function testLogoutForgetsTheRegisteredSessionOfThisContextOnly(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'sub', 'sid-1', 'customer', 'c1000000000000000000000000000001', self::PRE_LOGOUT_TOKEN, '5c000000000000000000000000000001');
        $other = $this->registry->register('a1000000000000000000000000000001', 'sub', 'sid-2', 'customer', 'c1000000000000000000000000000001', 'other-device-token', '5c000000000000000000000000000001');

        $this->route($this->provider('https://auth.example/logout'))->logout($this->context('c1000000000000000000000000000001'), new RequestDataBag());

        self::assertEquals([$other], SqliteSessionRegistry::sessionsOf($this->registry, 'customer', 'c1000000000000000000000000000001'));
    }

    public function testProviderPostLogoutUrlOverridesTheLoginPageAndCarriesASignedState(): void
    {
        $this->rememberLogin('id-token');
        $provider = $this->provider('https://idp.example/oidc/end-session');
        $provider->setPostLogoutUrl('https://shop.example/sw6oidc/postlogout');

        $this->route($provider)->logout($this->context(), new RequestDataBag());

        parse_str((string) parse_url((string) $this->pending->pull(), PHP_URL_QUERY), $query);
        self::assertSame('https://shop.example/sw6oidc/postlogout', $query['post_logout_redirect_uri']);
        self::assertSame('id-token', $query['id_token_hint']);
        self::assertSame(PostLogoutState::TARGET_CUSTOMER, (new PostLogoutState('app-secret'))->parse(\is_string($query['state']) ? $query['state'] : null));
    }

    public function testResolvesLogoutUrlFromPreLogoutToken(): void
    {
        $this->rememberLogin('id-token');

        $response = $this->route($this->provider('https://auth.example/logout'))->logout($this->context(), new RequestDataBag());

        self::assertSame('fresh-token', $response->getToken());
        self::assertSame('https://auth.example/logout?rd=' . rawurlencode(self::LOGIN_URL), $this->pending->pull());
        self::assertSame([], SqliteSessionRegistry::sessionsOf($this->registry, 'customer', self::CUSTOMER_ID), 'the ended session leaves the registry');
    }

    public function testNoLogoutContextLeavesNoPendingRedirect(): void
    {
        $this->route($this->provider('https://auth.example/logout'))->logout($this->context(), new RequestDataBag());

        self::assertNull($this->pending->pull());
    }

    public function testInactiveProviderLeavesNoPendingRedirect(): void
    {
        $this->rememberLogin('id-token');

        $this->route(null)->logout($this->context(), new RequestDataBag());

        self::assertNull($this->pending->pull());
    }

    public function testFailedInnerLogoutKeepsLogoutContext(): void
    {
        $this->rememberLogin('id-token');

        $decorated = $this->createMock(AbstractLogoutRoute::class);
        $decorated->method('logout')->willThrowException(new \RuntimeException('boom'));

        try {
            $this->route($this->provider('https://auth.example/logout'), $decorated)->logout($this->context(), new RequestDataBag());
            self::fail('Expected the inner logout exception to propagate.');
        } catch (\RuntimeException) {
        }

        self::assertCount(1, SqliteSessionRegistry::sessionsOf($this->registry, 'customer', self::CUSTOMER_ID), 'a failed logout keeps the session registered');
        self::assertNull($this->pending->pull());
    }

    public function testStoreApiClientsGetTheIdpLogoutUrlAndTheIdpTokensAreRevoked(): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'sub', null, 'customer', self::CUSTOMER_ID, self::PRE_LOGOUT_TOKEN, null, 'id-token', 'idp-access', 'idp-refresh');
        $provider = $this->provider('https://idp.example/oidc/end-session');
        $provider->setRevocationEndpoint('https://idp.example/oidc/revoke');
        $provider->setPublicClient(true);
        $provider->setClientId('shop');

        $revoked = [];
        $httpClient = $this->createMock(OidcHttpClient::class);
        $httpClient->method('postFormIgnoringResponseBody')->willReturnCallback(static function (string $url, array $params) use (&$revoked): void {
            $revoked[] = [$params['token'], $params['token_type_hint']];
        });

        $response = $this->route($provider, null, $httpClient)->logout($this->context(), new RequestDataBag());

        self::assertStringStartsWith('https://idp.example/oidc/end-session?', (string) $response->getRedirectUrl());
        self::assertSame('fresh-token', $response->getToken());
        self::assertSame([['idp-refresh', 'refresh_token'], ['idp-access', 'access_token']], $revoked);
    }

    private function route(?Sw6OidcProviderEntity $provider, ?AbstractLogoutRoute $decorated = null, ?OidcHttpClient $httpClient = null): OidcLogoutRoute
    {
        if ($decorated === null) {
            $decorated = $this->createMock(AbstractLogoutRoute::class);
            $decorated->method('logout')->willReturn(new ContextTokenResponse('fresh-token'));
        }

        $resolver = $this->createMock(ProviderResolver::class);
        if ($provider === null) {
            $resolver->method('getActiveById')->willThrowException(new ProviderNotFoundException('gone'));
        } else {
            $resolver->method('getActiveById')->willReturn($provider);
        }

        $urlGenerator = $this->createMock(UrlGeneratorInterface::class);
        $urlGenerator->method('generate')->with('frontend.account.login.page')->willReturn(self::LOGIN_URL);

        return new OidcLogoutRoute(
            $decorated,
            $resolver,
            new RpInitiatedLogoutService($httpClient ?? $this->createMock(OidcHttpClient::class), new NullLogger(), new PostLogoutState('app-secret')),
            $this->pending,
            $urlGenerator,
            new NullLogger(),
            $this->registry,
            $this->createStub(Sw6OidcSessionActivityRecorder::class),
        );
    }

    private function provider(string $endSessionEndpoint): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('a1000000000000000000000000000001');
        $provider->setClientId('shop-client');
        $provider->setEndSessionEndpoint($endSessionEndpoint);
        $provider->setLogoutStyle(str_ends_with($endSessionEndpoint, '/logout') ? Sw6OidcProviderDefinition::LOGOUT_STYLE_AUTHELIA_FORWARD_AUTH : Sw6OidcProviderDefinition::LOGOUT_STYLE_STANDARD);

        return $provider;
    }

    private function rememberLogin(?string $idToken): void
    {
        $this->registry->register('a1000000000000000000000000000001', 'sub', null, 'customer', self::CUSTOMER_ID, self::PRE_LOGOUT_TOKEN, null, $idToken);
    }

    private function context(?string $customerId = self::CUSTOMER_ID): SalesChannelContext
    {
        $context = $this->createMock(SalesChannelContext::class);
        $context->method('getToken')->willReturn(self::PRE_LOGOUT_TOKEN);

        if ($customerId !== null) {
            $customer = new CustomerEntity();
            $customer->setId($customerId);
            $context->method('getCustomer')->willReturn($customer);
        }

        $context->method('getContext')->willReturn(Context::createDefaultContext());

        return $context;
    }
}
