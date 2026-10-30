<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\FreshLoginNotConfirmedException;

/**
 * A re-authentication round trip (`prompt=login`) only proves a fresh login
 * if the IdP says so: the id_token's `auth_time` must be after the round
 * trip started. An IdP that ignores `prompt=login` would otherwise satisfy
 * it silently with an old session (R3-M5). No `max_age`: Authelia treats
 * `max_age=0` as "login always required" and never completes the flow.
 * Instead, `auth_time` is requested as an essential claim where the IdP
 * supports the `claims` parameter (OIDC Core §5.5, R8-L32). Shared by the
 * Administration step-up and the Storefront re-authentication.
 */
final class AuthTimeValidator
{
    /** Tolerated clock difference between IdP and shop. */
    public const LEEWAY_SECONDS = 60;

    /**
     * Authorize parameters of a re-authentication round trip.
     *
     * @return array<string, string>
     */
    public static function freshLoginParameters(Sw6OidcProviderEntity $provider): array
    {
        $parameters = ['prompt' => 'login'];

        if ($provider->isClaimsParameterSupported()) {
            $parameters['claims'] = (string) json_encode(['id_token' => ['auth_time' => ['essential' => true]]]);
        }

        return $parameters;
    }

    /**
     * @throws FreshLoginNotConfirmedException when the IdP didn't confirm a fresh login
     */
    public static function assertFresh(OidcCallbackResult $result): void
    {
        $authTime = $result->idTokenClaims['auth_time'] ?? null;

        if (!\is_int($authTime) || $authTime < $result->flow->startedAt - self::LEEWAY_SECONDS) {
            throw new FreshLoginNotConfirmedException('The identity provider did not confirm a fresh login (auth_time).');
        }
    }
}
