<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\EventSubscriber;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressDefinition;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Shopware\Core\Framework\Routing\KernelListenerPriorities;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * A JIT-created customer whose IdP sent no address gets placeholder
 * addresses (`-`), flagged in their custom fields (M16). They must never
 * reach an order (R3-M16):
 *
 * - the checkout confirm page sends a customer with a flagged billing or
 *   shipping address to that address's edit form first;
 * - the flag goes away as soon as real values are written, by the customer,
 *   an admin or address sync.
 */
class PlaceholderAddressSubscriber implements EventSubscriberInterface
{
    private const CONFIRM_ROUTE = 'frontend.checkout.confirm.page';

    public function __construct(
        private readonly Connection $connection,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // After the sales channel context is resolved.
            KernelEvents::CONTROLLER => ['redirectFromCheckout', KernelListenerPriorities::KERNEL_CONTROLLER_EVENT_CONTEXT_RESOLVE - 10],
            CustomerAddressDefinition::ENTITY_NAME . '.written' => 'clearFlagOnRealValues',
        ];
    }

    public function redirectFromCheckout(ControllerEvent $event): void
    {
        $request = $event->getRequest();

        if (!$event->isMainRequest() || $request->attributes->get('_route') !== self::CONFIRM_ROUTE) {
            return;
        }

        $context = $request->attributes->get(PlatformRequest::ATTRIBUTE_SALES_CHANNEL_CONTEXT_OBJECT);
        $customer = $context instanceof SalesChannelContext ? $context->getCustomer() : null;

        if (!$customer instanceof CustomerEntity) {
            return;
        }

        $address = null;

        foreach ([$customer->getActiveBillingAddress(), $customer->getActiveShippingAddress()] as $candidate) {
            if ($candidate instanceof CustomerAddressEntity && ($candidate->getCustomFields()[CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD] ?? false)) {
                $address = $candidate;

                break;
            }
        }

        if (!$address instanceof \Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity) {
            return;
        }

        $session = $request->hasSession() ? $request->getSession() : null;

        if ($session instanceof FlashBagAwareSessionInterface) {
            $session->getFlashBag()->add('warning', $this->translator->trans('sw6oidc.checkout.completeAddress'));
        }

        $url = $this->urlGenerator->generate('frontend.account.address.edit.page', ['addressId' => $address->getId()]);
        $event->setController(static fn (): RedirectResponse => new RedirectResponse($url));
    }

    public function clearFlagOnRealValues(EntityWrittenEvent $event): void
    {
        $ids = [];

        foreach ($event->getWriteResults() as $result) {
            $payload = $result->getPayload();
            $street = $payload['street'] ?? null;
            $city = $payload['city'] ?? null;

            if (($street === null && $city === null) || $street === '-' || $city === '-') {
                continue;
            }

            $id = $result->getPrimaryKey();

            if (\is_string($id) && Uuid::isValid($id)) {
                $ids[] = Uuid::fromHexToBytes($id);
            }
        }

        if ($ids === []) {
            return;
        }

        $this->connection->executeStatement(
            'UPDATE `customer_address`
             SET `custom_fields` = JSON_REMOVE(`custom_fields`, :path)
             WHERE `id` IN (:ids) AND JSON_CONTAINS_PATH(`custom_fields`, \'one\', :path)',
            ['path' => '$.' . CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD, 'ids' => $ids],
            ['ids' => ArrayParameterType::BINARY],
        );
    }
}
