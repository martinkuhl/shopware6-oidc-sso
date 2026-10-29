<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

/**
 * Binds a login round trip to the browser that started it (M1): the flow
 * start sets an HttpOnly, SameSite=Lax cookie with a random value, the flow
 * (and the admin login nonce) stores its hash, and the callback / nonce
 * exchange only proceed when the same browser presents it. Without this an
 * attacker could finish their own IdP login in a victim's browser (login
 * CSRF) or hand the victim a nonce for the attacker's session.
 *
 * Lax is sent on the IdP's top-level redirect back and on same-origin XHR.
 * The cookie is reused for its lifetime, so parallel tabs share it. On HTTPS
 * it uses the `__Host-` prefix (Secure, Path=/, no Domain).
 */
class BrowserBinding
{
    public const COOKIE_NAME = 'sw6oidc_binding';
    public const SECURE_COOKIE_NAME = '__Host-sw6oidc_binding';

    /** Request attribute holding a freshly minted value until the response sets it. */
    public const PENDING_ATTRIBUTE = '_sw6oidc_binding_pending';

    private const LIFETIME_SECONDS = 1800;

    public function __construct(private readonly RequestStack $requestStack)
    {
    }

    /**
     * The hash to store with a new flow, or null outside an HTTP request
     * (CLI, tests), where nothing can be bound.
     */
    public function bindCurrentBrowser(): ?string
    {
        $request = $this->requestStack->getCurrentRequest();

        if (!$request instanceof Request) {
            return null;
        }

        $value = $this->currentValue($request) ?? bin2hex(random_bytes(32));
        // Also for a reused value: re-issuing extends the cookie, so a flow
        // started late in its lifetime doesn't fail as "different browser" (R3-L3).
        $request->attributes->set(self::PENDING_ATTRIBUTE, $value);

        return $this->hash($value);
    }

    /**
     * Whether the current request comes from the browser a stored hash was
     * bound to. A null hash (flow started outside a request) always matches.
     */
    public function matchesCurrentBrowser(?string $storedHash): bool
    {
        if ($storedHash === null) {
            return true;
        }

        $request = $this->requestStack->getCurrentRequest();
        $value = $request instanceof Request ? $this->currentValue($request) : null;

        return $value !== null && hash_equals($storedHash, $this->hash($value));
    }

    /**
     * Called on the response: sets the cookie minted during this request.
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
            time() + self::LIFETIME_SECONDS,
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
        return hash('sha256', 'sw6oidc/binding/' . $value);
    }
}
