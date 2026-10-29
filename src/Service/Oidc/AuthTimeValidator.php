<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;

/**
 * A re-authentication round trip (`prompt=login`) only proves a fresh login
 * if the IdP says so: the id_token's `auth_time` must be after the round
 * trip started. An IdP that ignores `prompt=login` would otherwise satisfy
 * it silently with an old session (R3-M5). No `max_age=0`: Authelia treats
 * it as "login always required" and never completes the flow. Shared by the
 * Administration step-up and the Storefront re-authentication.
 */
final class AuthTimeValidator
{
    /** Tolerated clock difference between IdP and shop. */
    public const LEEWAY_SECONDS = 60;

    /**
     * @throws InvalidStateException when the IdP didn't confirm a fresh login
     */
    public static function assertFresh(OidcCallbackResult $result): void
    {
        $authTime = $result->idTokenClaims['auth_time'] ?? null;

        if (!\is_int($authTime) || $authTime < $result->flow->startedAt - self::LEEWAY_SECONDS) {
            throw new InvalidStateException('The identity provider did not confirm a fresh login (auth_time).');
        }
    }
}
