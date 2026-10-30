<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Subscriber\StatelessEndpointSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

#[CoversClass(StatelessEndpointSubscriber::class)]
final class StatelessEndpointSubscriberTest extends TestCase
{
    /**
     * R8-L18: cookie-less machine calls must not leave a PHP session behind.
     */
    public function testMachineEndpointsGetAnInMemorySession(): void
    {
        foreach (['/sw6oidc/health', '/sw6oidc/backchannel-logout', '/sw6oidc/frontchannel-logout/'] as $path) {
            self::assertTrue($this->isInMemory($this->sessionAfter($path)), $path);
        }

        self::assertFalse($this->isInMemory($this->sessionAfter('/account/login')), 'every other page keeps the real session');
    }

    public function testTheInMemorySessionAnnouncesNoCookie(): void
    {
        $request = Request::create('/sw6oidc/health');
        $response = new Response();
        $response->headers->setCookie(Cookie::create('SW6OIDC_STATELESS', 'x'));
        $response->headers->setCookie(Cookie::create('other', 'y'));

        (new StatelessEndpointSubscriber())->dropSessionCookie(new ResponseEvent($this->createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST, $response));

        self::assertSame(['other'], array_map(static fn (Cookie $cookie): string => $cookie->getName(), $response->headers->getCookies()));
    }

    private function sessionAfter(string $path): SessionInterface
    {
        $request = Request::create($path);
        $request->setSession(new Session(new NativeSessionStorage()));
        (new StatelessEndpointSubscriber())->useMemorySession(new RequestEvent($this->createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST));

        return $request->getSession();
    }

    private function isInMemory(SessionInterface $session): bool
    {
        return $session instanceof Session && (new \ReflectionProperty(Session::class, 'storage'))->getValue($session) instanceof MockArraySessionStorage;
    }
}
