<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * Explicit "Connect SSO": the IdP subject is already bound to a different
 * account of the same type.
 */
class SubjectAlreadyLinkedException extends Sw6OidcException
{
    protected const STATUS_CODE = 409;
    protected const ERROR_CODE = 'SW6OIDC_SUBJECT_ALREADY_LINKED';
}
