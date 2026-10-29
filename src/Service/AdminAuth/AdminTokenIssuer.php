<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtPayloadReader;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Response;

/**
 * Mints a real Administration OAuth token response for a user the caller has
 * already verified (OIDC login nonce, passkey assertion, step-up), through
 * the plugin's AuthorizationServer and AdminOidcGrant. The one place that
 * builds the grant request, so the client, grant type and scope handling
 * can't drift between callers.
 *
 * The grant request is built from scratch, never converted from the client's
 * HTTP request: the bridge builds a JSON request's parsed body from the raw
 * content and ignores anything set on the parameter bag (R3-H1), and the
 * server must not trust a client-sent grant type, client id or scope.
 */
class AdminTokenIssuer
{
    private const CLIENT_ID = 'administration';
    private const SCOPE = 'write';

    private readonly Psr17Factory $psr17Factory;

    public function __construct(
        private readonly AuthorizationServer $adminAuthorizationServer,
    ) {
        $this->psr17Factory = new Psr17Factory();
    }

    /**
     * @param bool $stepUp a fresh re-authentication: short-lived `user-verified` token, no refresh token
     *
     * @throws OAuthServerException
     */
    public function issue(string $userId, bool $stepUp = false): Response
    {
        $psrRequest = $this->psr17Factory->createServerRequest('POST', '/api/oauth/token')
            ->withParsedBody([
                'grant_type' => AdminOidcGrant::GRANT_IDENTIFIER,
                'client_id' => self::CLIENT_ID,
                // The grant replaces the scope of a step-up token itself.
                'scope' => self::SCOPE,
            ])
            ->withAttribute(AdminOidcGrant::REQUEST_ATTRIBUTE_USER_ID, $userId)
            ->withAttribute(AdminOidcGrant::REQUEST_ATTRIBUTE_STEP_UP, $stepUp);

        $tokenResponse = $this->adminAuthorizationServer->respondToAccessTokenRequest($psrRequest, $this->psr17Factory->createResponse());

        return (new HttpFoundationFactory())->createResponse($tokenResponse);
    }

    /**
     * The `jti` of the access token in a token response issued here, or null.
     */
    public static function accessTokenJti(Response $tokenResponse): ?string
    {
        $payload = json_decode((string) $tokenResponse->getContent(), true);
        $accessToken = \is_array($payload) ? ($payload['access_token'] ?? null) : null;

        return \is_string($accessToken) ? JwtPayloadReader::stringClaim($accessToken, 'jti') : null;
    }
}
