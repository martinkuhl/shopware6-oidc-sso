<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;

/**
 * Client authentication for a POST to the token or revocation endpoint (RFC
 * 6749 §2.3.1, RFC 7009 §2.1), in exactly one place so the two calls can't
 * drift: a public client has no secret and identifies itself via client_id
 * in the body; a confidential client sends its credentials either in the
 * Authorization header (`client_secret_basic`) or in the body
 * (`client_secret_post`), never both.
 */
final readonly class ClientAuthentication
{
    /**
     * @param array<string, string> $bodyParams
     */
    private function __construct(
        public array $bodyParams,
        public ?string $basicAuthUsername,
        public ?string $basicAuthPassword,
    ) {
    }

    /**
     * @param string      $authMethod Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_*
     * @param string|null $secret     the usable client secret; ignored for public clients
     */
    public static function forProvider(Sw6OidcProviderEntity $provider, string $authMethod, ?string $secret): self
    {
        if ($provider->isPublicClient()) {
            return new self(['client_id' => $provider->getClientId()], null, null);
        }

        if ($authMethod === Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_POST) {
            return new self(['client_id' => $provider->getClientId(), 'client_secret' => $secret ?? ''], null, null);
        }

        return new self([], $provider->getClientId(), $secret ?? '');
    }
}
