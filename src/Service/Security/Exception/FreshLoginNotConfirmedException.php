<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

/**
 * A re-authentication round trip (Administration step-up, Storefront
 * re-auth) came back without an `auth_time` from after its start: the IdP
 * didn't confirm a fresh login. Not an attack signal (the IdP simply doesn't
 * send the claim, or answered from its session), so callers show their own
 * message and don't count it on the rate limiter (R8-L32).
 */
class FreshLoginNotConfirmedException extends InvalidStateException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_FRESH_LOGIN_NOT_CONFIRMED';
}
