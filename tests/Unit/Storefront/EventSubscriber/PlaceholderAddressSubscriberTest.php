<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Storefront\EventSubscriber;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use MartinKuhl\Sw6Oidc\Storefront\EventSubscriber\PlaceholderAddressSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * R3-M16: placeholder addresses never reach an order.
 */
#[CoversClass(PlaceholderAddressSubscriber::class)]
final class PlaceholderAddressSubscriberTest extends TestCase
{
    public function testCheckoutWithAPlaceholderAddressGoesToTheAddressForm(): void
    {
        $event = $this->confirmPage(placeholder: true);

        $response = ($event->getController())();
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/account/address/addr-1', $response->getTargetUrl());
        $session = $event->getRequest()->getSession();
        self::assertInstanceOf(Session::class, $session);
        self::assertSame(['completeAddress'], $session->getFlashBag()->peek('warning'));
    }

    public function testCheckoutWithARealAddressIsUntouched(): void
    {
        $event = $this->confirmPage(placeholder: false);

        self::assertInstanceOf(Response::class, ($event->getController())());
        self::assertNotInstanceOf(RedirectResponse::class, ($event->getController())());
    }

    private function confirmPage(bool $placeholder): ControllerEvent
    {
        $address = new CustomerAddressEntity();
        $address->setId('addr-1');
        $address->setCustomFields($placeholder ? [CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD => true] : []);
        $customer = new CustomerEntity();
        $customer->setActiveBillingAddress($address);
        $customer->setActiveShippingAddress($address);
        $context = $this->createStub(SalesChannelContext::class);
        $context->method('getCustomer')->willReturn($customer);

        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $request->attributes->set('_route', 'frontend.checkout.confirm.page');
        $request->attributes->set(PlatformRequest::ATTRIBUTE_SALES_CHANNEL_CONTEXT_OBJECT, $context);

        $urls = $this->createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(static fn (string $route, array $parameters): string => '/account/address/' . $parameters['addressId']);
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturn('completeAddress');

        $event = new ControllerEvent($this->createStub(HttpKernelInterface::class), static fn (): Response => new Response('confirm'), $request, HttpKernelInterface::MAIN_REQUEST);
        (new PlaceholderAddressSubscriber($this->createStub(Connection::class), $urls, $translator))->redirectFromCheckout($event);

        return $event;
    }
}
