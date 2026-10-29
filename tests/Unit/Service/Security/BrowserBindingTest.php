<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginNonceService;
use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(BrowserBinding::class)]
#[CoversClass(OidcSecurityHelper::class)]
#[CoversClass(AdminLoginNonceService::class)]
final class BrowserBindingTest extends TestCase
{
    private RequestStack $requests;

    private BrowserBinding $binding;

    protected function setUp(): void
    {
        $this->requests = new RequestStack();
        $this->binding = new BrowserBinding($this->requests);
    }

    public function testFlowStartSetsAnHttpOnlyLaxCookie(): void
    {
        $request = Request::create('https://shop.example/sw6oidc/login');
        $this->requests->push($request);

        self::assertNotNull($this->binding->bindCurrentBrowser());

        $response = new Response();
        $this->binding->applyPendingCookie($request, $response);
        $cookie = $response->headers->getCookies()[0] ?? null;

        self::assertInstanceOf(Cookie::class, $cookie);
        self::assertSame(BrowserBinding::SECURE_COOKIE_NAME, $cookie->getName());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        self::assertSame('/', $cookie->getPath());
    }

    public function testCallbackFromTheSameBrowserMatchesAndFromAnotherDoesNot(): void
    {
        [$hash, $cookieValue] = $this->startFlow();

        $this->requests->push(Request::create('https://shop.example/sw6oidc/callback', cookies: [BrowserBinding::SECURE_COOKIE_NAME => $cookieValue]));
        self::assertTrue($this->binding->matchesCurrentBrowser($hash));

        $this->requests->push(Request::create('https://shop.example/sw6oidc/callback'));
        self::assertFalse($this->binding->matchesCurrentBrowser($hash), 'no cookie');

        $this->requests->push(Request::create('https://shop.example/sw6oidc/callback', cookies: [BrowserBinding::SECURE_COOKIE_NAME => str_repeat('a', 64)]));
        self::assertFalse($this->binding->matchesCurrentBrowser($hash), 'another browser');

        self::assertTrue($this->binding->matchesCurrentBrowser(null), 'flows started outside a request are not bound');
    }

    public function testAnExistingCookieIsReusedForParallelFlows(): void
    {
        [$first, $cookieValue] = $this->startFlow();

        $request = Request::create('https://shop.example/sw6oidc/login', cookies: [BrowserBinding::SECURE_COOKIE_NAME => $cookieValue]);
        $this->requests->push($request);

        self::assertSame($first, $this->binding->bindCurrentBrowser());
        // Same value, re-issued so the cookie's lifetime starts again (R3-L3).
        self::assertSame($cookieValue, $request->attributes->get(BrowserBinding::PENDING_ATTRIBUTE));
    }

    public function testCallbackInAnotherBrowserIsRejectedBySecurityHelper(): void
    {
        $helper = new OidcSecurityHelper(new InMemoryAtomicCache(), $this->binding);

        $this->requests->push(Request::create('https://shop.example/sw6oidc/login'));
        $state = $helper->beginAuthorizationRequest('provider-1', 'customer', '/', 'S256')['state'];

        $this->requests->push(Request::create('https://shop.example/sw6oidc/callback'));

        $this->expectException(InvalidStateException::class);
        $this->expectExceptionMessage('different browser');

        $helper->consumeAuthorizationFlow($state);
    }

    public function testAdminNonceIsOnlyRedeemableFromTheBoundBrowser(): void
    {
        [$hash, $cookieValue] = $this->startFlow();
        $nonces = new AdminLoginNonceService(new InMemoryAtomicCache(), $this->binding);

        $stolen = $nonces->createNonce('user-1', null, null, $hash);
        $this->requests->push(Request::create('https://shop.example/api/sw6oidc/admin/token', 'POST'));
        self::assertNull($nonces->redeemNonce($stolen));

        $own = $nonces->createNonce('user-1', null, null, $hash);
        $this->requests->push(Request::create('https://shop.example/api/sw6oidc/admin/token', 'POST', cookies: [BrowserBinding::SECURE_COOKIE_NAME => $cookieValue]));
        self::assertSame('user-1', $nonces->redeemNonce($own)?->userId);
    }

    /**
     * @return array{string, string} the stored hash and the cookie value the browser got
     */
    private function startFlow(): array
    {
        $request = Request::create('https://shop.example/sw6oidc/login');
        $this->requests->push($request);
        $hash = $this->binding->bindCurrentBrowser();
        \assert(\is_string($hash));

        $value = $request->attributes->get(BrowserBinding::PENDING_ATTRIBUTE);
        \assert(\is_string($value));

        return [$hash, $value];
    }
}
