<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * A confidential client has no usable client_secret: it is empty, or still
 * an encrypted envelope after hydration, i.e. it could not be decrypted with
 * the current APP_SECRET (rotated, or a row copied from another
 * installation). The admin has to re-enter it.
 */
class ClientSecretUnavailableException extends Sw6OidcException
{
    protected const STATUS_CODE = 503;
    protected const ERROR_CODE = 'SW6OIDC_CLIENT_SECRET_UNAVAILABLE';

    public static function forProvider(string $providerId): self
    {
        return new self(sprintf(
            'The client secret of OIDC provider %s is missing or cannot be decrypted (was APP_SECRET changed?). Re-enter the client secret in the provider settings.',
            $providerId,
        ));
    }
}
