<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Session;

use MartinKuhl\Sw6Oidc\Service\Session\SessionAuthenticationClock;
use MartinKuhl\Sw6Oidc\Subscriber\CustomerAuthenticationClockSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\Event\CustomerLoginEvent;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * R3-M5: the "freshly authenticated" window belongs to one browser session,
 * not to the account — core shares one context token between all logins of
 * a customer, so the context can't tell them apart.
 */
#[CoversClass(SessionAuthenticationClock::class)]
#[CoversClass(CustomerAuthenticationClockSubscriber::class)]
final class SessionAuthenticationClockTest extends TestCase
{
    public function testALoginMakesExactlyThatBrowserSessionFresh(): void
    {
        $victim = $this->browser();
        $attacker = $this->browser();

        (new SessionAuthenticationClock($victim))->markAuthenticated('customer-1');

        self::assertTrue((new SessionAuthenticationClock($victim))->isFresh($this->context('customer-1')));
        self::assertFalse((new SessionAuthenticationClock($attacker))->isFresh($this->context('customer-1')));
    }

    public function testTheStampBelongsToTheCustomerWhoLoggedIn(): void
    {
        $browser = $this->browser();
        (new SessionAuthenticationClock($browser))->markAuthenticated('customer-1');

        self::assertFalse((new SessionAuthenticationClock($browser))->isFresh($this->context('customer-2')));
    }

    public function testTheWindowExpires(): void
    {
        $browser = $this->browser();
        $browser->getMainRequest()?->getSession()->set('sw6oidc_authenticated_at', ['customerId' => 'customer-1', 'at' => time() - 601]);
        $clock = new SessionAuthenticationClock($browser);

        self::assertFalse($clock->isFresh($this->context('customer-1')));
        self::assertTrue($clock->isFresh($this->context('customer-1'), 3600));
    }

    /**
     * R8-H2: an admin's "login as customer" must not let them attach their
     * own passkey or IdP identity to the account.
     */
    public function testAnImitatedSessionIsNeverFreshAndAnImitationLoginStampsNothing(): void
    {
        $browser = $this->browser();
        $clock = new SessionAuthenticationClock($browser);
        $clock->markAuthenticated('customer-1');

        self::assertFalse($clock->isFresh($this->context('customer-1', imitatingUserId: 'admin-1')));

        $fresh = $this->browser();
        $imitated = $this->context('customer-1', imitatingUserId: 'admin-1');
        $customer = $imitated->getCustomer();
        \assert($customer instanceof CustomerEntity);
        (new CustomerAuthenticationClockSubscriber(new SessionAuthenticationClock($fresh)))->onLogin(new CustomerLoginEvent($imitated, $customer, 'token'));

        self::assertFalse((new SessionAuthenticationClock($fresh))->isFresh($this->context('customer-1')));

        (new CustomerAuthenticationClockSubscriber(new SessionAuthenticationClock($fresh)))->onLogin(new CustomerLoginEvent($this->context('customer-1'), $customer, 'token'));
        self::assertTrue((new SessionAuthenticationClock($fresh))->isFresh($this->context('customer-1')));
    }

    public function testNoSessionMeansNotFresh(): void
    {
        $clock = new SessionAuthenticationClock(new RequestStack());
        $clock->markAuthenticated('customer-1');

        self::assertFalse($clock->isFresh($this->context('customer-1')));
    }

    private function browser(): RequestStack
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $stack = new RequestStack();
        $stack->push($request);

        return $stack;
    }

    private function context(string $customerId, ?string $imitatingUserId = null): SalesChannelContext
    {
        $customer = new CustomerEntity();
        $customer->setId($customerId);
        $context = $this->createStub(SalesChannelContext::class);
        $context->method('getCustomer')->willReturn($customer);
        $context->method('getImitatingUserId')->willReturn($imitatingUserId);

        return $context;
    }
}
