<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\ClientSecretUnavailableException;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;

/**
 * Exchanges an authorization code (+ PKCE verifier) for tokens at the provider's
 * token endpoint. A confidential client authenticates the way the provider's
 * `token_endpoint_auth_method` says (RFC 6749 §2.3.1): HTTP Basic by default —
 * the de facto default for Authelia, Keycloak, and most other IdPs — or
 * client_id/client_secret in the body. Public clients (RFC 6749 §2.1) send
 * client_id in the body with no Authorization header, since they have no
 * secret to authenticate with. See ClientAuthentication.
 */
class TokenExchangeService
{
    public function __construct(private readonly OidcHttpClient $httpClient)
    {
    }

    /**
     * The response shape below is only the happy-path expectation, never a
     * guarantee - this is raw decoded JSON from a third-party IdP's token
     * endpoint (see OidcHttpClient::postForm()'s own untyped
     * array<string, mixed> return), so every field including access_token
     * is genuinely optional as far as the type system is concerned; callers
     * must keep validating presence before use.
     *
     * @return array{access_token?: string, id_token?: string, refresh_token?: string, expires_in?: int}
     */
    public function exchangeCodeForTokens(
        Sw6OidcProviderEntity $provider,
        string $code,
        string $redirectUri,
        string $codeVerifier,
    ): array {
        $authentication = ClientAuthentication::forProvider($provider, $provider->getTokenEndpointAuthMethod(), $this->clientSecret($provider));

        $params = array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ], $authentication->bodyParams);

        return $this->httpClient->postForm(
            (string) $provider->getAccessTokenEndpoint(),
            $params,
            $provider->getHttpTimeout(),
            $authentication->basicAuthUsername,
            $authentication->basicAuthPassword,
        );
    }

    private function clientSecret(Sw6OidcProviderEntity $provider): ?string
    {
        if ($provider->isPublicClient()) {
            return null;
        }

        // Still an envelope after hydration = undecryptable with the current
        // APP_SECRET. Fail with an actionable error instead of sending the
        // ciphertext to the IdP and getting an opaque invalid_client back.
        $secret = $provider->getUsableClientSecret();

        if ($secret === null && Sw6OidcEncryptor::isEnvelope((string) $provider->getClientSecret())) {
            throw ClientSecretUnavailableException::forProvider($provider->getId());
        }

        return $secret;
    }
}
