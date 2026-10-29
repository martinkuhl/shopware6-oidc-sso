<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provider\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class ProviderNotFoundException extends Sw6OidcException
{
    protected const STATUS_CODE = 404;
    protected const ERROR_CODE = 'SW6OIDC_PROVIDER_NOT_FOUND';
}
