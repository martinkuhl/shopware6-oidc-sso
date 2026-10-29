<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Service;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLoginRoute;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;

/**
 * Decorates core's password LoginRoute (Storefront form + Store API
 * /store-api/account/login) to enforce disable_non_oidc_customer_login.
 * OIDC and Passkey logins don't go through this route at all — they use
 * core's AccountService::loginById() directly — so they're unaffected.
 */
class PasswordLoginGuardLoginRoute extends AbstractLoginRoute
{
    public function __construct(
        private readonly AbstractLoginRoute $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
    ) {
    }

    public function getDecorated(): AbstractLoginRoute
    {
        return $this->decorated;
    }

    public function login(#[\SensitiveParameter] RequestDataBag $data, SalesChannelContext $context): ContextTokenResponse
    {
        if ($this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Customer->value, $context->getContext())) {
            throw new PasswordLoginDisabledException();
        }

        return $this->decorated->login($data, $context);
    }
}
