<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use Shopware\Core\Framework\Context;

/**
 * A passkey login never asks the IdP, so offboarding a user there (or
 * deactivating the provider) doesn't stop it. With `passkeyRequiresActiveSso`
 * on, an SSO-connected account logs in with a passkey only while its
 * provider is active and serves that login type. Accounts without a binding
 * are unaffected.
 */
class PasskeyLoginPolicy
{
    public function __construct(
        private readonly PasskeyConfig $passkeyConfig,
        private readonly UserProviderBindingService $bindingService,
        private readonly ProviderResolver $providerResolver,
    ) {
    }

    public function allows(string $userType, string $userId, Context $context): bool
    {
        if (!$this->passkeyConfig->requiresActiveSso()) {
            return true;
        }

        $providerId = $this->bindingService->getBoundProviderId($userType, $userId, $context);

        if ($providerId === null) {
            return true;
        }

        try {
            $this->providerResolver->getActiveById($providerId, $userType, $context);
        } catch (ProviderNotFoundException) {
            return false;
        }

        return true;
    }
}
