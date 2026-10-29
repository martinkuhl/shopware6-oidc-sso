<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\PasswordLoginGuardUserRepository;
use MartinKuhl\Sw6Oidc\Storefront\Service\PasswordLoginGuardLoginRoute;
use MartinKuhl\Sw6Oidc\Storefront\Service\PasswordLoginGuardRegisterConfirmRoute;
use MartinKuhl\Sw6Oidc\Storefront\Service\PasswordLoginGuardRegisterRoute;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\NullLogger;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterConfirmRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterRoute;
use MartinKuhl\Sw6Oidc\Subscriber\AdminPasswordLoginGuardSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLoginRoute;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\Test\Generator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

#[CoversClass(PasswordLoginPolicy::class)]
#[CoversClass(PasswordLoginGuardLoginRoute::class)]
#[CoversClass(AdminPasswordLoginGuardSubscriber::class)]
#[CoversClass(PasswordLoginDisabledException::class)]
#[CoversClass(PasswordLoginGuardUserRepository::class)]
#[CoversClass(PasswordLoginGuardRegisterRoute::class)]
#[CoversClass(PasswordLoginGuardRegisterConfirmRoute::class)]
final class PasswordLoginEnforcementTest extends TestCase
{
    public function testPolicyIsOnWhenAnyActiveProviderSetsTheFlag(): void
    {
        $policy = new PasswordLoginPolicy($this->resolverWith([$this->provider(false, false), $this->provider(true, false)]));

        self::assertTrue($policy->isPasswordLoginDisabled('admin', Generator::generateSalesChannelContext()->getContext()));
        self::assertFalse($policy->isPasswordLoginDisabled('customer', Generator::generateSalesChannelContext()->getContext()));
    }

    public function testBreakGlassOverridesThePolicy(): void
    {
        $policy = new PasswordLoginPolicy($this->resolverWith([$this->provider(true, true)]), true);

        self::assertFalse($policy->isPasswordLoginDisabled('admin', Generator::generateSalesChannelContext()->getContext()));
    }

    public function testStorefrontPasswordLoginIsRejectedWhenDisabled(): void
    {
        $inner = $this->createMock(AbstractLoginRoute::class);
        $inner->expects(self::never())->method('login');
        $route = new PasswordLoginGuardLoginRoute($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(false, true)])));

        try {
            $route->login(new RequestDataBag(), Generator::generateSalesChannelContext());
            self::fail('Expected PasswordLoginDisabledException');
        } catch (PasswordLoginDisabledException $exception) {
            self::assertSame(403, $exception->getStatusCode());
            self::assertSame(PasswordLoginDisabledException::ERROR_CODE, $exception->getErrorCode());
            self::assertStringContainsString('single sign-on', $exception->getMessage());
            self::assertSame('sw6oidc.login.passwordLoginDisabled', $exception->getSnippetKey());
        }
    }

    public function testStorefrontPasswordLoginPassesThroughWhenEnabled(): void
    {
        $inner = $this->createMock(AbstractLoginRoute::class);
        $inner->expects(self::once())->method('login')->willReturn(new ContextTokenResponse('token'));
        $route = new PasswordLoginGuardLoginRoute($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)])));

        self::assertSame('token', $route->login(new RequestDataBag(), Generator::generateSalesChannelContext())->getToken());
        self::assertSame($inner, $route->getDecorated());
    }

    public function testAdminPasswordGrantIsRejectedWhenDisabled(): void
    {
        $event = $this->tokenRequest('password');
        (new AdminPasswordLoginGuardSubscriber(new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]))))->onRequest($event);

        self::assertNotNull($event->getResponse());
        self::assertSame(403, $event->getResponse()->getStatusCode());
        self::assertStringContainsString(AdminPasswordLoginGuardSubscriber::ERROR_CODE, (string) $event->getResponse()->getContent());
    }

    public function testAdminRefreshGrantIsNotAffected(): void
    {
        $event = $this->tokenRequest('refresh_token');
        (new AdminPasswordLoginGuardSubscriber(new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]))))->onRequest($event);

        self::assertNull($event->getResponse());
    }

    public function testOtherRoutesAreNotAffected(): void
    {
        $event = $this->tokenRequest('password', 'api.info.config');
        (new AdminPasswordLoginGuardSubscriber(new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]))))->onRequest($event);

        self::assertNull($event->getResponse());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function jsonContentTypes(): iterable
    {
        yield 'application/json' => ['application/json'];
        yield 'application/x-json (N-H1)' => ['application/x-json'];
        yield 'application/vnd.api+json' => ['application/vnd.api+json'];
    }

    #[DataProvider('jsonContentTypes')]
    public function testAdminPasswordGrantIsRejectedWhateverTheJsonContentType(string $contentType): void
    {
        $request = new Request([], [], [], [], [], ['CONTENT_TYPE' => $contentType], (string) json_encode(['grant_type' => 'password', 'username' => 'admin', 'password' => 'x']));
        $request->attributes->set('_route', 'api.oauth.token');
        $event = new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);

        (new AdminPasswordLoginGuardSubscriber(new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]))))->onRequest($event);

        self::assertSame(403, $event->getResponse()?->getStatusCode());
    }

    public function testUndeterminableGrantTypeIsRefusedWhileDisabled(): void
    {
        $request = new Request([], [], [], [], [], ['CONTENT_TYPE' => 'application/json'], '{not json');
        $request->attributes->set('_route', 'api.oauth.token');
        $event = new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);

        (new AdminPasswordLoginGuardSubscriber(new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]))))->onRequest($event);

        self::assertSame(403, $event->getResponse()?->getStatusCode());
    }

    public function testUserAccessKeyClientCredentialsAreRefusedWhileDisabled(): void
    {
        $policy = new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)]));

        $userKey = $this->tokenRequest('client_credentials', body: ['client_id' => 'SWUAABCDEF', 'client_secret' => 'x']);
        (new AdminPasswordLoginGuardSubscriber($policy))->onRequest($userKey);
        self::assertSame(403, $userKey->getResponse()?->getStatusCode());

        $integrationKey = $this->tokenRequest('client_credentials', body: ['client_id' => 'SWIAABCDEF', 'client_secret' => 'x']);
        (new AdminPasswordLoginGuardSubscriber($policy))->onRequest($integrationKey);
        self::assertNull($integrationKey->getResponse());

        $optOut = $this->tokenRequest('client_credentials', body: ['client_id' => 'SWUAABCDEF', 'client_secret' => 'x']);
        (new AdminPasswordLoginGuardSubscriber($policy, true))->onRequest($optOut);
        self::assertNull($optOut->getResponse());
    }

    public function testUserRepositoryDecoratorRefusesCredentialsWhileDisabled(): void
    {
        $inner = $this->createMock(UserRepositoryInterface::class);
        $inner->expects(self::never())->method('getUserEntityByUserCredentials');

        $repository = new PasswordLoginGuardUserRepository($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(true, false)])), new NullLogger());

        self::assertNull($repository->getUserEntityByUserCredentials('admin', 'shopware', 'password', $this->createStub(ClientEntityInterface::class)));
    }

    public function testUserRepositoryDecoratorDelegatesWhileEnabled(): void
    {
        $inner = $this->createMock(UserRepositoryInterface::class);
        $inner->expects(self::once())->method('getUserEntityByUserCredentials');

        $repository = new PasswordLoginGuardUserRepository($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(false, false)])), new NullLogger());
        $repository->getUserEntityByUserCredentials('admin', 'shopware', 'password', $this->createStub(ClientEntityInterface::class));
    }

    public function testRegistrationIsRefusedWhileCustomerPasswordLoginIsDisabled(): void
    {
        $inner = $this->createMock(AbstractRegisterRoute::class);
        $inner->expects(self::never())->method('register');

        $this->expectException(PasswordLoginDisabledException::class);

        (new PasswordLoginGuardRegisterRoute($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(false, true)]))))
            ->register(new RequestDataBag(['email' => 'a@example.com']), Generator::generateSalesChannelContext());
    }

    public function testGuestCheckoutStaysAllowed(): void
    {
        $inner = $this->createMock(AbstractRegisterRoute::class);
        $inner->expects(self::once())->method('register');

        (new PasswordLoginGuardRegisterRoute($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(false, true)]))))
            ->register(new RequestDataBag(['guest' => true]), Generator::generateSalesChannelContext());
    }

    public function testRegistrationConfirmationIsRefusedWhileDisabled(): void
    {
        $inner = $this->createMock(AbstractRegisterConfirmRoute::class);
        $inner->expects(self::never())->method('confirm');

        $this->expectException(PasswordLoginDisabledException::class);

        (new PasswordLoginGuardRegisterConfirmRoute($inner, new PasswordLoginPolicy($this->resolverWith([$this->provider(false, true)]))))
            ->confirm(new RequestDataBag(), Generator::generateSalesChannelContext());
    }

    /**
     * @param array<string, mixed>|null $body
     */
    private function tokenRequest(string $grantType, string $route = 'api.oauth.token', ?array $body = null): RequestEvent
    {
        if ($body !== null) {
            $request = new Request([], ['grant_type' => $grantType, ...$body]);
            $request->attributes->set('_route', $route);

            return new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
        }

        $request = new Request([], ['grant_type' => $grantType]);
        $request->attributes->set('_route', $route);

        return new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
    }

    /**
     * @param list<Sw6OidcProviderEntity> $providers
     */
    private function resolverWith(array $providers): ProviderResolver
    {
        $resolver = $this->createMock(ProviderResolver::class);
        $resolver->method('getActiveProviders')->willReturn($providers);

        return $resolver;
    }

    private function provider(bool $disableAdmin, bool $disableCustomer): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setDisableNonOidcAdminLogin($disableAdmin);
        $provider->setDisableNonOidcCustomerLogin($disableCustomer);

        return $provider;
    }
}
