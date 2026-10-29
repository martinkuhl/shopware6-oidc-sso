<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * An account with the IdP's email already exists but may not be linked
 * automatically (the provider doesn't allow linking, the email isn't
 * verified, the account is a superadmin, or it is bound to another subject).
 * The owner has to connect the provider from their own, logged-in account.
 */
class AccountLinkingRequiredException extends Sw6OidcException
{
    protected const STATUS_CODE = 403;
    protected const ERROR_CODE = 'SW6OIDC_ACCOUNT_LINKING_REQUIRED';
}
