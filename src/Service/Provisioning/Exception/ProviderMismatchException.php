<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * Thrown when a user tries to log in via an OIDC provider other than the one
 * that first authenticated (or created) their account — per-user IdP binding.
 */
class ProviderMismatchException extends Sw6OidcException
{
    protected const STATUS_CODE = 409;
    protected const ERROR_CODE = 'SW6OIDC_PROVIDER_MISMATCH';
}
