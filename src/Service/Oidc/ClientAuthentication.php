<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\ClientSecretUnavailableException;

/**
 * Client authentication for a POST to the token or revocation endpoint (RFC
 * 6749 §2.3.1, RFC 7009 §2.1), in exactly one place so the two calls can't
 * drift — the secret lookup included: a public client has no secret and
 * identifies itself via client_id in the body; a confidential client sends
 * its credentials either in the Authorization header (`client_secret_basic`)
 * or in the body (`client_secret_post`), never both.
 */
final readonly class ClientAuthentication
{
    /**
     * @param array<string, string> $bodyParams
     */
    private function __construct(
        public array $bodyParams,
        public ?string $authorizationHeader,
    ) {
    }

    /**
     * @param string $authMethod Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_*
     *
     * @throws ClientSecretUnavailableException a confidential client whose secret is empty or can't be decrypted:
     *                                          never send an empty secret or the envelope to the IdP (N-L5)
     */
    public static function forProvider(Sw6OidcProviderEntity $provider, string $authMethod): self
    {
        if ($provider->isPublicClient()) {
            return new self(['client_id' => $provider->getClientId()], null);
        }

        $secret = $provider->getUsableClientSecret();

        if ($secret === null) {
            throw ClientSecretUnavailableException::forProvider($provider->getId());
        }

        if ($authMethod === Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_POST) {
            return new self(['client_id' => $provider->getClientId(), 'client_secret' => $secret], null);
        }

        return new self([], self::basicAuthorization($provider->getClientId(), $secret));
    }

    /**
     * RFC 6749 §2.3.1: client id and secret are form-urlencoded before they
     * are joined and base64-encoded. IdPs decode them again (fosite/Authelia,
     * Keycloak), so a secret with `+`, `%` or `:` only survives encoded
     * (R8-M1).
     */
    public static function basicAuthorization(string $clientId, #[\SensitiveParameter] string $secret): string
    {
        return 'Basic ' . base64_encode(rawurlencode($clientId) . ':' . rawurlencode($secret));
    }
}
