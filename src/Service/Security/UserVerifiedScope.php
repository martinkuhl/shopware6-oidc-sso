<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope as CoreUserVerifiedScope;
use Shopware\Core\PlatformRequest;
use Symfony\Component\HttpFoundation\Request;

/**
 * Whether the current Admin API request carries a `user-verified` token —
 * core's marker for "the user re-authenticated moments ago" (password
 * confirmation, or this plugin's step-up). Checked the same way core's own
 * UserController does for sensitive user writes.
 */
final class UserVerifiedScope
{
    public static function isPresent(Request $request): bool
    {
        $scopes = $request->attributes->get(PlatformRequest::ATTRIBUTE_OAUTH_SCOPES);

        return \is_array($scopes) && \in_array(CoreUserVerifiedScope::IDENTIFIER, $scopes, true);
    }
}
