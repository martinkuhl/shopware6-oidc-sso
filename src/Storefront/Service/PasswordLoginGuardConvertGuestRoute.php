<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractConvertGuestRoute;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\DataValidationDefinition;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SalesChannel\SuccessResponse;

/**
 * Converting a guest into a registered customer gives the account a password
 * and keeps it logged in: registration by another door, so blocked while
 * SSO-only mode is on, like PasswordLoginGuardRegisterRoute (R8-M11). Guest
 * checkout itself stays allowed.
 */
class PasswordLoginGuardConvertGuestRoute extends AbstractConvertGuestRoute
{
    public function __construct(
        private readonly AbstractConvertGuestRoute $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
    ) {
    }

    public function getDecorated(): AbstractConvertGuestRoute
    {
        return $this->decorated;
    }

    public function convertGuest(
        RequestDataBag $requestDataBag,
        SalesChannelContext $context,
        CustomerEntity $customer,
        ?DataValidationDefinition $additionalValidationDefinitions = null,
    ): SuccessResponse {
        if ($this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Customer->value, $context->getContext())) {
            throw new PasswordLoginDisabledException();
        }

        return $this->decorated->convertGuest($requestDataBag, $context, $customer, $additionalValidationDefinitions);
    }
}
