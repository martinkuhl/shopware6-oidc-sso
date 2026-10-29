<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use Psr\Log\LoggerInterface;

/**
 * Shared RP-Initiated Logout (OIDC RP-Initiated Logout + RFC 7009 revocation),
 * session-agnostic so both the Storefront customer logout subscriber and the
 * Administration logout listener can use it, including Authelia
 * forward-auth detection.
 */
class RpInitiatedLogoutService
{
    private const REVOCATION_TIMEOUT_SECONDS = 3;

    public function __construct(
        private readonly OidcHttpClient $httpClient,
        private readonly LoggerInterface $logger,
        private readonly PostLogoutState $postLogoutState,
    ) {
    }

    /**
     * @param string $defaultPostLogoutRedirectUri used unless the provider sets its own `post_logout_url`
     * @param PostLogoutState::TARGET_* $target which login page the shared `/sw6oidc/postlogout` landing picks
     */
    public function buildLogoutUrl(Sw6OidcProviderEntity $provider, ?string $idToken, string $defaultPostLogoutRedirectUri, string $target): ?string
    {
        $endSessionEndpoint = $provider->getEndSessionEndpoint();

        if ($endSessionEndpoint === null || $endSessionEndpoint === '') {
            return null;
        }

        $override = $provider->getPostLogoutUrl();
        $postLogoutRedirectUri = $override !== null && $override !== '' ? $override : $defaultPostLogoutRedirectUri;
        $state = $this->postLogoutState->create($target);

        if ($provider->getLogoutStyle() === Sw6OidcProviderDefinition::LOGOUT_STYLE_AUTHELIA_FORWARD_AUTH) {
            // `rd` is followed verbatim, so the shared landing gets its state as a query parameter.
            if (str_ends_with((string) parse_url($postLogoutRedirectUri, PHP_URL_PATH), '/sw6oidc/postlogout')) {
                $postLogoutRedirectUri .= $this->querySeparator($postLogoutRedirectUri) . http_build_query(['state' => $state]);
            }

            return $endSessionEndpoint . $this->querySeparator($endSessionEndpoint) . http_build_query([
                'rd' => $postLogoutRedirectUri,
            ]);
        }

        // client_id always: without an id_token (the admin fallback path)
        // Keycloak and others need it to accept post_logout_redirect_uri (R3-M3).
        $params = [
            'client_id' => $provider->getClientId(),
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'state' => $state,
        ];

        if ($idToken !== null) {
            $params['id_token_hint'] = $idToken;
        }

        return $endSessionEndpoint . $this->querySeparator($endSessionEndpoint) . http_build_query($params);
    }

    /**
     * RFC 7009 revocation of the login's IdP tokens (refresh token first —
     * revoking it usually invalidates the access token too). Fire-and-forget:
     * a failed revocation must never block the user from logging out.
     */
    public function revokeTokens(Sw6OidcProviderEntity $provider, LogoutContext $logoutContext): void
    {
        $this->revokeToken($provider, $logoutContext->idpRefreshToken, 'refresh_token');
        $this->revokeToken($provider, $logoutContext->idpAccessToken, 'access_token');
    }

    private function revokeToken(Sw6OidcProviderEntity $provider, ?string $token, string $tokenTypeHint): void
    {
        if ($token === null || $token === '') {
            return;
        }

        $revocationEndpoint = $provider->getRevocationEndpoint();

        if ($revocationEndpoint === null || $revocationEndpoint === '') {
            return;
        }

        $secret = $provider->isPublicClient() ? null : $provider->getUsableClientSecret();

        if (!$provider->isPublicClient() && $secret === null) {
            // Undecryptable secret: never send the envelope to the IdP (N-L5).
            $this->logger->warning('sw6oidc: RFC 7009 revocation skipped, the client secret is unavailable.', ['providerId' => $provider->getId()]);

            return;
        }

        // RFC 7009 §2.1 uses the token endpoint's client authentication, but
        // IdPs like Authelia register the method per endpoint, hence the
        // provider's own `revocation_endpoint_auth_method`.
        $authentication = ClientAuthentication::forProvider($provider, $provider->getRevocationEndpointAuthMethod(), $secret);

        try {
            $this->httpClient->postFormIgnoringResponseBody(
                $revocationEndpoint,
                ['token' => $token, 'token_type_hint' => $tokenTypeHint] + $authentication->bodyParams,
                // Runs inside the user's logout request: an unreachable IdP
                // may cost seconds, never twice the provider timeout (R3-L33).
                min($provider->getHttpTimeout(), self::REVOCATION_TIMEOUT_SECONDS),
                $authentication->basicAuthUsername,
                $authentication->basicAuthPassword,
                self::REVOCATION_TIMEOUT_SECONDS,
            );
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: RFC 7009 token revocation failed (non-fatal).', [
                'providerId' => $provider->getId(),
                'exception' => $exception->getMessage(),
            ]);
        }
    }


    private function querySeparator(string $url): string
    {
        return str_contains($url, '?') ? '&' : '?';
    }
}
