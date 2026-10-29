<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\CustomerResponse;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\DataValidationDefinition;
use Shopware\Core\System\SalesChannel\SalesChannelContext;

/**
 * Registration creates a password account and logs it in without going
 * through LoginRoute, so SSO-only mode (disable_non_oidc_customer_login)
 * blocks it here too. Guest checkout (`guest: true`) creates no password
 * account and stays allowed.
 */
class PasswordLoginGuardRegisterRoute extends AbstractRegisterRoute
{
    public function __construct(
        private readonly AbstractRegisterRoute $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
    ) {
    }

    public function getDecorated(): AbstractRegisterRoute
    {
        return $this->decorated;
    }

    public function register(
        RequestDataBag $data,
        SalesChannelContext $context,
        bool $validateStorefrontUrl = true,
        ?DataValidationDefinition $additionalValidationDefinitions = null,
    ): CustomerResponse {
        if (!$data->getBoolean('guest') && $this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Customer->value, $context->getContext())) {
            throw new PasswordLoginDisabledException();
        }

        return $this->decorated->register($data, $context, $validateStorefrontUrl, $additionalValidationDefinitions);
    }
}
