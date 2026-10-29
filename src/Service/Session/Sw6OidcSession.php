<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

/**
 * One OIDC login as the session registry remembers it: which IdP subject /
 * IdP session (`sid`) it belongs to, and which local session it created.
 *
 * `sessionKey` is the sales-channel context token (customer) or the jti of
 * the first access token minted for the login (admin). For admins the entry
 * `id` doubles as the login-session handle the Administration receives with
 * its token response: unlike the jti it survives token refreshes, so logout
 * can end exactly this session. The IdP tokens are kept for RFC 7009
 * revocation at logout.
 */
final readonly class Sw6OidcSession
{
    public const USER_TYPE_CUSTOMER = 'customer';
    public const USER_TYPE_ADMIN = 'admin';

    public function __construct(
        public string $id,
        public string $providerId,
        public string $sub,
        public ?string $sid,
        /** 'customer' | 'admin' */
        public string $userType,
        public string $userId,
        public string $sessionKey,
        public ?string $salesChannelId = null,
        public ?string $idToken = null,
        public int $createdAt = 0,
        public ?string $idpAccessToken = null,
        public ?string $idpRefreshToken = null,
    ) {
    }
}
