<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\CustomerException;

/**
 * Shopware's "bind customers to sales channel" setting: a customer with a
 * boundSalesChannelId may only log in to that sales channel. One place for
 * the rule, used by provisioning (email lookup) and the passwordless login.
 */
final class CustomerSalesChannelBinding
{
    public static function allows(CustomerEntity $customer, string $salesChannelId): bool
    {
        $boundSalesChannelId = $customer->getBoundSalesChannelId();

        return $boundSalesChannelId === null || $boundSalesChannelId === $salesChannelId;
    }

    /**
     * What an SSO or passkey login checks before core's
     * AccountService::loginById() (which also lets guests in): a real
     * account that may use this sales channel.
     *
     * @throws CustomerException
     */
    public static function assertCanLogIn(CustomerEntity $customer, string $salesChannelId): void
    {
        if ($customer->getGuest() || !self::allows($customer, $salesChannelId)) {
            throw CustomerException::badCredentials();
        }
    }
}
