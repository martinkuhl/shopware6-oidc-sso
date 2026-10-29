<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Twig;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Contracts\Translation\TranslatorInterface;
use Symfony\Contracts\Service\ResetInterface;
use Twig\Extension\RuntimeExtensionInterface;

/**
 * Lets the Storefront login template decide whether to show its "Login with
 * SSO"/"Login with Passkey" buttons at all - unlike the Administration
 * (email-scoped) case, the Storefront login page is anonymous with no
 * customer identity yet, so this can only ever answer "is SSO/Passkey login
 * configured/enabled for this sales channel AND (for passkey) has at least
 * one customer actually registered one", never anything about whether the
 * not-yet-identified visitor specifically has a passkey registered. Mirrors
 * OidcAdminAuthController::loginOptions()'s same reasoning on the
 * Administration side.
 *
 * A Twig runtime (StorefrontLoginOptionsExtension declares the functions), so
 * its services are only built when a template calls one — not on every Twig
 * boot, mail rendering included (R3-L46). Results are memoised per request:
 * the login form, header and account pages ask several times (R3-L47).
 */
class StorefrontLoginOptionsRuntime implements RuntimeExtensionInterface, ResetInterface
{
    /** @var array<string, mixed> */
    private array $memo = [];

    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly PasskeyConfig $passkeyConfig,
        private readonly PasskeyCredentialRepository $passkeyCredentialRepository,
        private readonly TranslatorInterface $translator,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
        private readonly UserProviderBindingService $bindingService,
    ) {
    }

    public function reset(): void
    {
        $this->memo = [];
    }

    /**
     * One button per visible provider, ordered by sortOrder — labeled
     * "Login with {displayName}" so "Login with SSO" doesn't get shown for
     * every configured IdP regardless of which one it actually is; only
     * ever falls back to the plain generic string if a provider has no
     * displayName set (there's nothing to interpolate into the pattern).
     *
     * @return array<int, array{id: string, label: string}>
     */
    public function getSsoProviders(SalesChannelContext $context): array
    {
        return $this->memo['providers:' . $context->getSalesChannelId() . ':' . $context->getLanguageId()] ??= array_map(
            fn (Sw6OidcProviderEntity $provider): array => [
                'id' => $provider->getId(),
                'label' => $provider->getDisplayName() !== null && $provider->getDisplayName() !== ''
                    ? $this->translator->trans('sw6oidc.login.buttonWithProvider', ['%name%' => $provider->getDisplayName()])
                    : $this->translator->trans('sw6oidc.login.button'),
            ],
            $this->providerResolver->getVisibleProviders(LoginType::Customer->value, $context->getContext()),
        );
    }

    /**
     * Passkeys switched on for this sales channel (account sidebar link).
     */
    public function isPasskeyEnabled(SalesChannelContext $context): bool
    {
        return $this->passkeyConfig->isEnabledForCustomer($context->getSalesChannelId());
    }

    public function isPasskeyAvailable(SalesChannelContext $context): bool
    {
        return $this->memo['passkey:' . $context->getSalesChannelId()] ??= $this->passkeyConfig->isEnabledForCustomer($context->getSalesChannelId())
            && $this->passkeyCredentialRepository->existsForUserType(LoginType::Customer->value, $context->getContext());
    }

    public function isPasswordLoginDisabled(SalesChannelContext $context): bool
    {
        return $this->memo['passwordDisabled'] ??= $this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Customer->value, $context->getContext());
    }

    /**
     * The account page's "Single sign-on" card: whether the logged-in
     * customer is connected to a provider, else which providers they can
     * connect explicitly ("Connect SSO").
     *
     * @return array{bound: bool, boundLabel: string|null, providers: list<array{id: string, label: string}>}
     */
    public function getAccountSso(SalesChannelContext $context): array
    {
        $customer = $context->getCustomer();

        if (!$customer instanceof \Shopware\Core\Checkout\Customer\CustomerEntity || $customer->getGuest()) {
            return ['bound' => false, 'boundLabel' => null, 'providers' => []];
        }

        $providers = $this->providerResolver->getVisibleProviders(LoginType::Customer->value, $context->getContext());
        $boundProviderId = $this->bindingService->getBoundProviderId(LoginType::Customer->value, $customer->getId(), $context->getContext());

        if ($boundProviderId !== null) {
            $label = null;

            foreach ($providers as $provider) {
                if ($provider->getId() === $boundProviderId) {
                    $label = $provider->getDisplayName() ?: $provider->getAppName();
                }
            }

            return ['bound' => true, 'boundLabel' => $label ?? $this->translator->trans('sw6oidc.login.button'), 'providers' => []];
        }

        return [
            'bound' => false,
            'boundLabel' => null,
            'providers' => array_values(array_map(
                static fn (Sw6OidcProviderEntity $provider): array => [
                    'id' => $provider->getId(),
                    'label' => $provider->getDisplayName() ?: $provider->getAppName(),
                ],
                $providers,
            )),
        ];
    }
}
