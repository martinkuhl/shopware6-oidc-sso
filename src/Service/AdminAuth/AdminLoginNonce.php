<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

/**
 * What a redeemed admin login nonce carries: the verified admin user, and —
 * for OIDC logins — the provider and the pending session registry entry the
 * callback created, which the token exchange completes with the minted
 * access token's jti (see OidcAdminAuthController::exchangeNonce()).
 */
final readonly class AdminLoginNonce
{
    public function __construct(
        public string $userId,
        public ?string $providerId = null,
        public ?string $registrySessionId = null,
    ) {
    }
}
