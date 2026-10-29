<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

/**
 * The callback's `state` is missing or matches no stored flow (unknown,
 * expired or already used). Nothing was looked up or written for it, so
 * the callbacks don't count it towards the rate limit: otherwise anyone
 * could block an address's SSO logins with junk requests (N-M3).
 */
class UnknownStateException extends InvalidStateException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_UNKNOWN_STATE';
}
