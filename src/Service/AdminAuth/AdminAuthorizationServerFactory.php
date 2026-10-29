<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

/**
 * Builds a real `league/oauth2-server` AuthorizationServer — the actual
 * third-party package Shopware's own Admin API OAuth is built on, used
 * directly rather than reimplemented — wired to Shopware's own OAuth
 * repositories/signing key, with our AdminOidcGrant registered on it.
 *
 * A factory (not a plain XML service definition) only because
 * AuthorizationServer::enableGrantType() needs a \DateInterval argument,
 * which isn't constructible from services.xml.
 *
 * The access-token TTL is the shop's own `shopware.api.access_token_ttl`, so
 * SSO sessions follow the same policy as password logins (H10).
 */
class AdminAuthorizationServerFactory
{
    public function __construct(
        private readonly ClientRepositoryInterface $clientRepository,
        private readonly AccessTokenRepositoryInterface $accessTokenRepository,
        private readonly ScopeRepositoryInterface $scopeRepository,
        private readonly CryptKeyInterface $privateKey,
        private readonly string $encryptionKey,
        private readonly AdminOidcGrant $grant,
        private readonly string $accessTokenTtl,
    ) {
    }

    public function create(): AuthorizationServer
    {
        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->encryptionKey,
        );

        $server->enableGrantType($this->grant, new \DateInterval($this->accessTokenTtl));

        return $server;
    }
}
