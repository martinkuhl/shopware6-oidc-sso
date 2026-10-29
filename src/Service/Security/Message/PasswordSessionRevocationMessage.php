<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Message;

use Shopware\Core\Framework\MessageQueue\AsyncMessageInterface;

/**
 * Password login of this user type just became disabled: end the sessions
 * of accounts without an SSO binding. Queued, so the provider save that
 * triggered it doesn't run a shop-wide update inside the admin's request
 * (R3-M21).
 */
final readonly class PasswordSessionRevocationMessage implements AsyncMessageInterface
{
    public function __construct(public string $userType)
    {
    }
}
