<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Declares the Storefront login-option functions. The logic and its
 * services live in StorefrontLoginOptionsRuntime, which Twig only builds
 * when a template calls one of them (R3-L46).
 */
class StorefrontLoginOptionsExtension extends AbstractExtension
{
    public function getFunctions(): array
    {
        return [
            new TwigFunction('sw6oidc_storefront_sso_providers', [StorefrontLoginOptionsRuntime::class, 'getSsoProviders']),
            new TwigFunction('sw6oidc_storefront_passkey_available', [StorefrontLoginOptionsRuntime::class, 'isPasskeyAvailable']),
            new TwigFunction('sw6oidc_storefront_passkey_enabled', [StorefrontLoginOptionsRuntime::class, 'isPasskeyEnabled']),
            new TwigFunction('sw6oidc_storefront_password_login_disabled', [StorefrontLoginOptionsRuntime::class, 'isPasswordLoginDisabled']),
            new TwigFunction('sw6oidc_storefront_account_sso', [StorefrontLoginOptionsRuntime::class, 'getAccountSso']),
        ];
    }
}
