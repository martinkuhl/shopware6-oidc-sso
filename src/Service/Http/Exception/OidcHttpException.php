<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Http\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class OidcHttpException extends Sw6OidcException
{
    protected const STATUS_CODE = 502;
    protected const ERROR_CODE = 'SW6OIDC_IDP_REQUEST_FAILED';
}
