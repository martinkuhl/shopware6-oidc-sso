<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Checkout\Cart;

use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use Shopware\Core\Checkout\Cart\Cart;
use Shopware\Core\Checkout\Cart\CartValidatorInterface;
use Shopware\Core\Checkout\Cart\Error\ErrorCollection;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\System\SalesChannel\SalesChannelContext;

/**
 * Placeholder addresses must never reach an order (R3-M16). The Storefront
 * confirm page already sends the customer to the address form
 * (PlaceholderAddressSubscriber), but the Store API, headless frontends,
 * express checkouts and a direct POST to the finish route never pass
 * through it: a blocking cart error covers every order path (R8-M5).
 */
class PlaceholderAddressCartValidator implements CartValidatorInterface
{
    public function validate(Cart $cart, ErrorCollection $errors, SalesChannelContext $context): void
    {
        $customer = $context->getCustomer();

        if (!$customer instanceof CustomerEntity) {
            return;
        }

        $seen = [];

        foreach ([$customer->getActiveBillingAddress(), $customer->getActiveShippingAddress()] as $address) {
            if (
                $address instanceof CustomerAddressEntity
                && !isset($seen[$address->getId()])
                && ($address->getCustomFields()[CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD] ?? false)
            ) {
                $seen[$address->getId()] = true;
                $errors->add(new PlaceholderAddressError($address->getId()));
            }
        }
    }
}
