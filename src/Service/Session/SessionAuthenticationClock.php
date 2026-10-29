<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * When the *current browser session* last proved who it is: a login of any
 * kind (password, OIDC, passkey) or a verified re-authentication round trip
 * (R3-M5). Sensitive account changes (adding a passkey, connecting SSO) need
 * a fresh proof, so a stolen session alone can't add a permanent way in, and
 * the victim logging in elsewhere doesn't open the window for the stolen
 * session (unlike the account-wide `customer.lastLogin`).
 *
 * Kept in the Storefront's PHP session, not in the sales channel context:
 * core gives every login of a customer in a sales channel the same context
 * token (CartRestorer reuses the existing context), so a stamp on the
 * context would be shared with whoever else holds that token.
 */
class SessionAuthenticationClock
{
    public const DEFAULT_WINDOW_SECONDS = 600;
    private const SESSION_KEY = 'sw6oidc_authenticated_at';

    public function __construct(private readonly RequestStack $requestStack)
    {
    }

    public function markAuthenticated(string $customerId): void
    {
        $request = $this->requestStack->getMainRequest();

        if ($request instanceof Request && $request->hasSession()) {
            $request->getSession()->set(self::SESSION_KEY, ['customerId' => $customerId, 'at' => time()]);
        }
    }

    public function isFresh(SalesChannelContext $context, int $windowSeconds = self::DEFAULT_WINDOW_SECONDS): bool
    {
        $request = $this->requestStack->getMainRequest();
        $customerId = $context->getCustomer()?->getId();

        if ($customerId === null || !$request instanceof Request || !$request->hasSession()) {
            return false;
        }

        $stamp = $request->getSession()->get(self::SESSION_KEY);

        return \is_array($stamp)
            && ($stamp['customerId'] ?? null) === $customerId
            && \is_int($stamp['at'] ?? null)
            && $stamp['at'] >= time() - $windowSeconds;
    }
}
