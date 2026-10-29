<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey\Exception;

/**
 * The account already has the maximum number of passkeys (R3-L13).
 */
class PasskeyLimitReachedException extends PasskeyCeremonyException
{
    protected const STATUS_CODE = 409;
    protected const ERROR_CODE = 'SW6OIDC_PASSKEY_LIMIT_REACHED';
}
