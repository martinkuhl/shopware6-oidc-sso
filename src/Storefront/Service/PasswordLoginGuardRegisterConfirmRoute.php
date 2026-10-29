<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterConfirmRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\CustomerResponse;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\SalesChannelContext;

/**
 * Double-opt-in confirmation logs the new password account in; blocked while
 * SSO-only mode is on (see PasswordLoginGuardRegisterRoute).
 */
class PasswordLoginGuardRegisterConfirmRoute extends AbstractRegisterConfirmRoute
{
    public function __construct(
        private readonly AbstractRegisterConfirmRoute $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
    ) {
    }

    public function getDecorated(): AbstractRegisterConfirmRoute
    {
        return $this->decorated;
    }

    public function confirm(RequestDataBag $dataBag, SalesChannelContext $context): CustomerResponse
    {
        if ($this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Customer->value, $context->getContext())) {
            throw new PasswordLoginDisabledException();
        }

        return $this->decorated->confirm($dataBag, $context);
    }
}
