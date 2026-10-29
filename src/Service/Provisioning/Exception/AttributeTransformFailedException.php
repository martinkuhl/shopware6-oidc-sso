<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * A transform on an identity attribute (email, username) failed. Falling
 * back to the raw IdP value would change which account the login resolves
 * to, so the login is refused instead.
 */
class AttributeTransformFailedException extends Sw6OidcException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_ATTRIBUTE_TRANSFORM_FAILED';
}
