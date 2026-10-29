<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class CustomerProvisioningDeniedException extends Sw6OidcException
{
    protected const STATUS_CODE = 403;
    protected const ERROR_CODE = 'SW6OIDC_CUSTOMER_PROVISIONING_DENIED';
}
