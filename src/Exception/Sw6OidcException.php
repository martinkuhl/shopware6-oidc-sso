<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Exception;

use Shopware\Core\Framework\HttpException;

/**
 * Base of the plugin's domain exceptions: Shopware HttpExceptions with a
 * stable `SW6OIDC_*` error code and HTTP status (R3-L10), so whatever escapes
 * a controller is a typed error response, not an anonymous 500. Subclasses
 * set STATUS_CODE and ERROR_CODE and are built with `new X($message, $previous)`.
 */
abstract class Sw6OidcException extends HttpException
{
    protected const STATUS_CODE = 400;
    protected const ERROR_CODE = 'SW6OIDC_ERROR';

    public function __construct(string $message = '', ?\Throwable $previous = null)
    {
        parent::__construct(static::STATUS_CODE, static::ERROR_CODE, $message, [], $previous);
    }
}
