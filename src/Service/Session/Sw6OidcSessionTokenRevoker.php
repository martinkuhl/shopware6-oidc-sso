<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Oidc\LogoutContext;
use MartinKuhl\Sw6Oidc\Service\Oidc\RpInitiatedLogoutService;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * RFC 7009 revocation of a customer registry entry's IdP tokens, through the
 * provider it logged in with: at logout, and when a further login on the
 * same device replaces the entry.
 */
class Sw6OidcSessionTokenRevoker
{
    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly RpInitiatedLogoutService $rpInitiatedLogoutService,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Revokes the session's IdP tokens (fire-and-forget); returns its
     * provider, or null when that is no longer active for customers.
     */
    public function revoke(Sw6OidcSession $session, Context $context): ?Sw6OidcProviderEntity
    {
        try {
            $provider = $this->providerResolver->getActiveById($session->providerId, LoginType::Customer->value, $context);
        } catch (ProviderNotFoundException $exception) {
            $this->logger->warning('sw6oidc: token revocation skipped, provider no longer active.', [
                'providerId' => $session->providerId,
                'exception' => $exception->getMessage(),
            ]);

            return null;
        }

        $this->rpInitiatedLogoutService->revokeTokens($provider, self::logoutContextOf($session));

        return $provider;
    }

    public static function logoutContextOf(Sw6OidcSession $session): LogoutContext
    {
        return new LogoutContext($session->providerId, $session->idToken, $session->idpAccessToken, $session->idpRefreshToken);
    }
}
