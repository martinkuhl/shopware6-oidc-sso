<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

/**
 * What RP-initiated logout needs about the login being ended: its provider,
 * and — when the session registry still has it — the id_token for
 * `id_token_hint` and the IdP tokens for RFC 7009 revocation.
 */
final readonly class LogoutContext
{
    public function __construct(
        public string $providerId,
        public ?string $idToken = null,
        public ?string $idpAccessToken = null,
        public ?string $idpRefreshToken = null,
    ) {
    }
}
