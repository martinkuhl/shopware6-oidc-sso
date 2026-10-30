<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;

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
        $authentication = ClientAuthentication::forProvider($provider, $provider->getTokenEndpointAuthMethod());

        $params = array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ], $authentication->bodyParams);

        $tokens = $this->httpClient->postForm(
            (string) $provider->getAccessTokenEndpoint(),
            $params,
            $provider->getHttpTimeout(),
            $authentication->authorizationHeader,
        );

        // The access token is sent to userinfo as a Bearer token: another
        // type (DPoP, MAC) would be used wrongly (RFC 6749 §5.1, RFC 6750).
        $tokenType = $tokens['token_type'] ?? null;

        if ($tokenType !== null && (!\is_string($tokenType) || strcasecmp($tokenType, 'Bearer') !== 0)) {
            throw new OidcHttpException(sprintf(
                'The token endpoint issued a "%s" token; only Bearer tokens are supported.',
                \is_string($tokenType) ? mb_substr($tokenType, 0, 32) : \gettype($tokenType),
            ));
        }

        return $tokens;
    }
}
