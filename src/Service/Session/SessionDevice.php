<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tells apart a customer's SSO logins on several devices. Core gives them
 * all the same context token (CartRestorer), so the token alone can't say
 * which login a logout comes from. Every Storefront SSO login sets an
 * HttpOnly, SameSite=Lax cookie with a random value, and its registry entry
 * stores the hash. The logout then sends the IdP logout (`id_token_hint`,
 * hence `sid`) of the login made in this browser, and a further login on the
 * same device replaces that device's entry.
 *
 * Local logout still ends every device: core ends the shared token. The
 * value is no credential; a planted one only changes which login's
 * `id_token_hint` is sent. A strictly necessary login cookie, like
 * BrowserBinding's, so it isn't registered with cookie consent. On HTTPS it
 * uses the `__Host-` prefix (Secure, Path=/, no Domain).
 */
class SessionDevice
{
    public const COOKIE_NAME = 'sw6oidc_device';
    public const SECURE_COOKIE_NAME = '__Host-sw6oidc_device';

    /** Request attribute holding the value until the response sets it. */
    public const PENDING_ATTRIBUTE = '_sw6oidc_device_pending';

    public function __construct(private readonly RequestStack $requestStack)
    {
    }

    /**
     * The device hash to register with a new login, or null outside an HTTP
     * request (CLI, tests). Re-issues the cookie, so it lives as long as the
     * newest login's registry entry can.
     */
    public function deviceForLogin(): ?string
    {
        $request = $this->requestStack->getCurrentRequest();

        if (!$request instanceof Request) {
            return null;
        }

        $value = $this->currentValue($request) ?? bin2hex(random_bytes(32));
        $request->attributes->set(self::PENDING_ATTRIBUTE, $value);

        return $this->hash($value);
    }

    /**
     * The hash of the device cookie this request presents, or null.
     */
    public function currentDevice(): ?string
    {
        $request = $this->requestStack->getCurrentRequest();
        $value = $request instanceof Request ? $this->currentValue($request) : null;

        return $value !== null ? $this->hash($value) : null;
    }

    /**
     * Called on the response: sets the cookie a login marked during this request.
     */
    public function applyPendingCookie(Request $request, Response $response): void
    {
        $value = $request->attributes->get(self::PENDING_ATTRIBUTE);

        if (!\is_string($value) || $value === '') {
            return;
        }

        $secure = $request->isSecure();

        $response->headers->setCookie(Cookie::create(
            $secure ? self::SECURE_COOKIE_NAME : self::COOKIE_NAME,
            $value,
            time() + Sw6OidcSessionRegistry::HARD_TTL_SECONDS,
            '/',
            null,
            $secure,
            true,
            false,
            Cookie::SAMESITE_LAX,
        ));
    }

    private function currentValue(Request $request): ?string
    {
        $pending = $request->attributes->get(self::PENDING_ATTRIBUTE);

        if (\is_string($pending) && $pending !== '') {
            return $pending;
        }

        $value = $request->cookies->get($request->isSecure() ? self::SECURE_COOKIE_NAME : self::COOKIE_NAME);

        return \is_string($value) && preg_match('/^[a-f0-9]{64}$/', $value) === 1 ? $value : null;
    }

    private function hash(string $value): string
    {
        return hash('sha256', 'sw6oidc/device/' . $value);
    }
}
