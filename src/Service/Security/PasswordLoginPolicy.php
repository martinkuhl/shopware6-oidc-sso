<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use Shopware\Core\Framework\Context;

/**
 * Whether native password login is disabled for a login type ('admin' or
 * 'customer'): true as soon as any *active* provider serving that login type
 * has disable_non_oidc_{admin,customer}_login set. Providers aren't scoped to
 * sales channels, so this is shop-wide. Passkey and OIDC logins are never
 * affected — only the password path.
 *
 * SW6OIDC_ALLOW_PASSWORD_LOGIN=1 is a break-glass override (IdP outage,
 * misconfigured provider) that re-enables password login without touching
 * the provider configuration.
 */
class PasswordLoginPolicy
{
    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly bool $breakGlassAllowPasswordLogin = false,
    ) {
    }

    public function isPasswordLoginDisabled(string $loginType, Context $context): bool
    {
        if ($this->breakGlassAllowPasswordLogin) {
            return false;
        }

        return array_filter(
            $this->providerResolver->getActiveProviders($loginType, $context),
            static fn (Sw6OidcProviderEntity $provider): bool => $loginType === LoginType::Admin->value
                ? $provider->isDisableNonOidcAdminLogin()
                : $provider->isDisableNonOidcCustomerLogin(),
        ) !== [];
    }
}
