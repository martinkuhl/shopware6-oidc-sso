<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Session;

use MartinKuhl\Sw6Oidc\Service\Session\SessionDevice;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(SessionDevice::class)]
final class SessionDeviceTest extends TestCase
{
    private RequestStack $requests;

    private SessionDevice $device;

    protected function setUp(): void
    {
        $this->requests = new RequestStack();
        $this->device = new SessionDevice($this->requests);
    }

    public function testALoginSetsALongLivedHttpOnlyLaxCookie(): void
    {
        $request = Request::create('https://shop.example/sw6oidc/callback');
        $this->requests->push($request);

        self::assertNotNull($this->device->deviceForLogin());

        $response = new Response();
        $this->device->applyPendingCookie($request, $response);
        $cookie = $response->headers->getCookies()[0] ?? null;

        self::assertInstanceOf(Cookie::class, $cookie);
        self::assertSame(SessionDevice::SECURE_COOKIE_NAME, $cookie->getName());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        self::assertSame('/', $cookie->getPath());
        self::assertGreaterThan(time() + Sw6OidcSessionRegistry::HARD_TTL_SECONDS - 60, $cookie->getExpiresTime());
    }

    public function testThePlainCookieNameIsUsedWithoutHttps(): void
    {
        $request = Request::create('http://shop.example/sw6oidc/callback');
        $this->requests->push($request);
        $this->device->deviceForLogin();

        $response = new Response();
        $this->device->applyPendingCookie($request, $response);

        self::assertSame(SessionDevice::COOKIE_NAME, $response->headers->getCookies()[0]?->getName());
    }

    public function testTheSameBrowserIsTheSameDeviceAndKeepsItsCookie(): void
    {
        $value = str_repeat('b', 64);
        $login = Request::create('https://shop.example/sw6oidc/callback', cookies: [SessionDevice::SECURE_COOKIE_NAME => $value]);
        $this->requests->push($login);
        $hash = $this->device->deviceForLogin();

        self::assertSame($value, $login->attributes->get(SessionDevice::PENDING_ATTRIBUTE), 're-issued with the same value');

        $this->requests->push(Request::create('https://shop.example/account/logout', cookies: [SessionDevice::SECURE_COOKIE_NAME => $value]));
        self::assertSame($hash, $this->device->currentDevice());

        $this->requests->push(Request::create('https://shop.example/account/logout', cookies: [SessionDevice::SECURE_COOKIE_NAME => str_repeat('c', 64)]));
        self::assertNotSame($hash, $this->device->currentDevice(), 'another device');
    }

    public function testMalformedOrMissingCookiesAreNoDevice(): void
    {
        $this->requests->push(Request::create('https://shop.example/account/logout'));
        self::assertNull($this->device->currentDevice());

        $this->requests->push(Request::create('https://shop.example/account/logout', cookies: [SessionDevice::SECURE_COOKIE_NAME => 'not-hex']));
        self::assertNull($this->device->currentDevice());

        // The plain name doesn't count on HTTPS.
        $this->requests->push(Request::create('https://shop.example/account/logout', cookies: [SessionDevice::COOKIE_NAME => str_repeat('d', 64)]));
        self::assertNull($this->device->currentDevice());
    }

    public function testNothingOutsideARequest(): void
    {
        self::assertNull($this->device->deviceForLogin());
        self::assertNull($this->device->currentDevice());
    }

    public function testNoPendingValueSetsNoCookie(): void
    {
        $response = new Response();
        $this->device->applyPendingCookie(Request::create('https://shop.example/'), $response);

        self::assertSame([], $response->headers->getCookies());
    }
}
