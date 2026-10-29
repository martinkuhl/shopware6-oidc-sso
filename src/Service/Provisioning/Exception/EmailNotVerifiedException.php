<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * The provider requires `email_verified: true` and the IdP didn't assert it
 * (a missing claim counts as unverified).
 */
class EmailNotVerifiedException extends Sw6OidcException
{
    protected const STATUS_CODE = 403;
    protected const ERROR_CODE = 'SW6OIDC_EMAIL_NOT_VERIFIED';
}
