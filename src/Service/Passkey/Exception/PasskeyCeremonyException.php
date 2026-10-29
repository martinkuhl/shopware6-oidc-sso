<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class PasskeyCeremonyException extends Sw6OidcException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_PASSKEY_CEREMONY_FAILED';
}
