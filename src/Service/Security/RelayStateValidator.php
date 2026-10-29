<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Symfony\Component\Routing\Exception\ExceptionInterface as RoutingException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Where to send the customer after an SSO login. The value travels through
 * the IdP round trip and comes from the login link's query, so it is
 * attacker-influenced: only same-site targets are accepted (H4).
 *
 * - A Storefront route name (`frontend.*`) plus parameters — what core's
 *   login form itself uses (`redirectTo`/`redirectParameters`) — is resolved
 *   to a path by the router.
 * - A path is accepted only if it is a plain absolute path: it must start
 *   with a single `/`, not `//` or `/\`, and contain no backslash, control
 *   character or whitespace — checked on the raw and the percent-decoded
 *   value, so `%09//evil`, `/%5Cevil` and friends are refused too.
 *
 * Anything else yields null (callers fall back to the account page).
 */
class RelayStateValidator
{
    // `D`: `$` must not match before a trailing newline (R3-L2).
    private const SAFE_PATH = '#^/(?![/\\\\])[^\x00-\x20\x7f\\\\]*$#D';
    private const ROUTE_NAME = '/^frontend\.[a-z0-9_.\-]+$/';

    public function __construct(private readonly UrlGeneratorInterface $urlGenerator)
    {
    }

    public function safePath(string $value): ?string
    {
        if ($value === '' || preg_match(self::SAFE_PATH, $value) !== 1) {
            return null;
        }

        $decoded = rawurldecode($value);

        return preg_match(self::SAFE_PATH, $decoded) === 1 ? $value : null;
    }

    /**
     * @param string $redirectTo         a Storefront route name or a path
     * @param mixed  $redirectParameters route parameters (array or JSON object string)
     */
    public function resolve(string $redirectTo, mixed $redirectParameters = null): ?string
    {
        if (preg_match(self::ROUTE_NAME, $redirectTo) === 1) {
            try {
                return $this->safePath($this->urlGenerator->generate($redirectTo, $this->parameters($redirectParameters)));
            } catch (RoutingException) {
                return null;
            }
        }

        return $this->safePath($redirectTo);
    }

    /**
     * @return array<string, scalar>
     */
    private function parameters(mixed $value): array
    {
        if (\is_string($value) && $value !== '') {
            try {
                $value = json_decode($value, true, 4, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return [];
            }
        }

        if (!\is_array($value)) {
            return [];
        }

        return array_filter($value, static fn (mixed $parameter, mixed $key): bool => \is_string($key) && \is_scalar($parameter), ARRAY_FILTER_USE_BOTH);
    }
}
