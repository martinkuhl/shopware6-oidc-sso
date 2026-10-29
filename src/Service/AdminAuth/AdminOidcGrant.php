<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Shopware\Core\Framework\Api\OAuth\ScopeRepository;
use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope;
use Shopware\Core\Framework\Api\OAuth\User\User as ShopwareOAuthUser;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * A custom `league/oauth2-server` grant that trusts a pre-verified Shopware
 * admin user id instead of a password. The id is carried as a PSR-7 request
 * attribute (see REQUEST_ATTRIBUTE_USER_ID), set by
 * Controller/Api/OidcAdminAuthController::exchangeNonce() immediately after
 * redeeming a one-time OIDC/Passkey login nonce.
 *
 * This is the crux of the whole Administration bridge: registering this
 * grant on an AuthorizationServer
 * built from Shopware's own real ClientRepository/AccessTokenRepository/
 * ScopeRepository/FakeCryptKey (see AdminAuthorizationServerFactory) means the
 * token this grant issues is a genuine Shopware access/refresh token pair,
 * indistinguishable from a normal password-grant login to the rest of the
 * system — never a faked or parallel token format.
 */
class AdminOidcGrant extends AbstractGrant
{
    public const GRANT_IDENTIFIER = 'sw6oidc_admin';
    public const REQUEST_ATTRIBUTE_USER_ID = 'sw6oidc_user_id';

    /**
     * Set (true) only by StepUpService after a fresh re-authentication:
     * the token then carries `user-verified`, lives at most five minutes and
     * comes without a refresh token. Any other caller never gets
     * `user-verified`, whatever scope the client asks for (N-M17).
     */
    public const REQUEST_ATTRIBUTE_STEP_UP = 'sw6oidc_step_up';

    private const STEP_UP_SCOPES = 'write user-verified';
    private const STEP_UP_MAX_TTL = 'PT5M';

    /**
     * @param string $refreshTokenTtl the shop's `shopware.api.refresh_token_ttl` (H10)
     */
    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly Connection $connection,
        string $refreshTokenTtl,
    ) {
        // AuthorizationServer::enableGrantType() never sets this - League
        // only wires up client/access-token/scope repositories, default
        // scope, private key and the emitter there. Every stock grant that
        // issues refresh tokens (PasswordGrant, RefreshTokenGrant, ...) sets
        // its own via setRefreshTokenRepository() in its constructor; without
        // it, AbstractGrant::issueRefreshToken() below throws "Typed property
        // ...::$refreshTokenRepository must not be accessed before
        // initialization" the first time a token is actually issued.
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new \DateInterval($refreshTokenTtl);
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $client = $this->validateClient($request);
        $user = $this->validateUser($request);
        $isStepUp = $request->getAttribute(self::REQUEST_ATTRIBUTE_STEP_UP) === true;

        if ($isStepUp) {
            $scopes = $this->validateScopes(self::STEP_UP_SCOPES);
            $accessTokenTTL = $this->shorterOf($accessTokenTTL, new \DateInterval(self::STEP_UP_MAX_TTL));
        } else {
            $requested = $this->getRequestParameter('scope', $request, $this->defaultScope);
            $scopes = $this->validateScopes(\is_string($requested) ? $this->withoutUserVerified($requested) : $requested);
        }

        // Shopware's ScopeRepository::finalizeScopes() only attaches `write`
        // for grant-type strings it recognizes (password, client_credentials
        // with write access, its own SSO grant); our own identifier
        // ('sw6oidc_admin') isn't one, so it would otherwise strip `write`
        // from the minted token even though the Administration SPA always
        // requests it - the next silent refresh through the real
        // /api/oauth/token then fails with invalid_scope, logging the admin
        // out early. Passing PASSWORD_GRANT here is correct, not a workaround:
        // this grant already fully vouches for the user via a pre-verified
        // OIDC/Passkey login, the same trust level as a password check.
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, ScopeRepository::PASSWORD_GRANT, $client, $user->getIdentifier());

        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        if ($isStepUp) {
            return $responseType;
        }

        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken instanceof \League\OAuth2\Server\Entities\RefreshTokenEntityInterface) {
            $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    public function getIdentifier(): string
    {
        return self::GRANT_IDENTIFIER;
    }

    private function withoutUserVerified(string $scopes): string
    {
        return implode(' ', array_filter(
            preg_split('/\s+/', trim($scopes)) ?: [],
            static fn (string $scope): bool => $scope !== '' && $scope !== UserVerifiedScope::IDENTIFIER,
        ));
    }

    private function shorterOf(\DateInterval $a, \DateInterval $b): \DateInterval
    {
        $now = new \DateTimeImmutable();

        return $now->add($a) <= $now->add($b) ? $a : $b;
    }

    /**
     * The caller verified *who* the user is (OIDC or WebAuthn); whether that
     * account may still log in is decided here, for every caller at once —
     * exactly like core's password grant refuses deleted and inactive users.
     */
    private function validateUser(ServerRequestInterface $request): UserEntityInterface
    {
        $userId = $request->getAttribute(self::REQUEST_ATTRIBUTE_USER_ID);

        if (!\is_string($userId) || !Uuid::isValid($userId)) {
            throw OAuthServerException::invalidRequest(self::REQUEST_ATTRIBUTE_USER_ID);
        }

        $active = $this->connection->fetchOne(
            'SELECT `active` FROM `user` WHERE `id` = :id',
            ['id' => Uuid::fromHexToBytes($userId)],
        );

        if ($userId === '' || $active === false || !(bool) $active) {
            throw OAuthServerException::invalidGrant('The user does not exist or is inactive.');
        }

        return new ShopwareOAuthUser($userId);
    }
}
