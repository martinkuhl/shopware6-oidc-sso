<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;

/**
 * Configuration completeness of a provider — purely local, **no outbound
 * HTTP**, so it is safe behind the unauthenticated health endpoint.
 */
class ProviderConfigInspector
{
    public function __construct(private readonly Sw6OidcEncryptor $encryptor)
    {
    }

    /**
     * @return list<string> machine-readable problem codes; [] = complete
     */
    public function problems(Sw6OidcProviderEntity $provider): array
    {
        $problems = [];
        $required = [
            'authorize_endpoint_missing' => $provider->getAuthorizeEndpoint(),
            'token_endpoint_missing' => $provider->getAccessTokenEndpoint(),
            'jwks_endpoint_missing' => $provider->getJwksEndpoint(),
            'issuer_missing' => $provider->getIssuer(),
            'client_id_missing' => $provider->getClientId(),
        ];

        foreach ($required as $code => $value) {
            if ($value === null || trim($value) === '') {
                $problems[] = $code;
            }
        }

        if (!$provider->isPublicClient()) {
            $secret = (string) $provider->getClientSecret();

            if ($secret === '') {
                $problems[] = 'client_secret_missing';
            } elseif ($this->encryptor->isEncrypted($secret)) {
                // Hydration passes an undecryptable envelope through unchanged (APP_SECRET rotated).
                $problems[] = 'client_secret_undecryptable';
            }
        }

        return $problems;
    }
}
