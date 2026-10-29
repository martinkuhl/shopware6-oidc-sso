<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

use Shopware\Core\Framework\HttpException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Password login (or password registration) is disabled because an active
 * OIDC provider has disable_non_oidc_{customer,admin}_login set.
 *
 * A plain 403 HttpException: Store API clients get the error code, and the
 * Storefront turns it into a flash message via
 * PasswordLoginDisabledExceptionSubscriber (it is deliberately not a
 * CustomerOptinNotCompletedException, whose handlers would treat it as a
 * pending double-opt-in).
 */
class PasswordLoginDisabledException extends HttpException
{
    public const ERROR_CODE = 'SW6OIDC_PASSWORD_LOGIN_DISABLED';

    public function __construct()
    {
        parent::__construct(
            Response::HTTP_FORBIDDEN,
            self::ERROR_CODE,
            'Password login is disabled for this shop. Please sign in with single sign-on.',
        );
    }

    public function getSnippetKey(): string
    {
        return 'sw6oidc.login.passwordLoginDisabled';
    }
}
