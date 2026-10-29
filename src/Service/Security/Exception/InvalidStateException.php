<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * Thrown when the OAuth `state` query parameter on a callback is missing, expired,
 * or already consumed — covers both CSRF protection and replay prevention, since
 * consumeAuthorizationFlow() atomically deletes the stored flow on first read.
 */
class InvalidStateException extends Sw6OidcException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_INVALID_STATE';
}
