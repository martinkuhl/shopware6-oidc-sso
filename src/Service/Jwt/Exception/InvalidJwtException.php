<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Jwt\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class InvalidJwtException extends Sw6OidcException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_INVALID_JWT';
}
