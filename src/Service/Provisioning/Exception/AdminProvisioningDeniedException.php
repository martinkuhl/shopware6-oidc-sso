<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

class AdminProvisioningDeniedException extends Sw6OidcException
{
    protected const STATUS_CODE = 403;
    protected const ERROR_CODE = 'SW6OIDC_ADMIN_PROVISIONING_DENIED';

    public const REASON_AUTO_CREATE_DISABLED = 'auto_create_disabled';
    public const REASON_NO_ROLE = 'no_role';
    public const REASON_ACCOUNT_MISSING = 'account_missing';
    public const REASON_ACCOUNT_INACTIVE = 'account_inactive';

    private function __construct(string $message, public readonly string $reason)
    {
        parent::__construct($message);
    }

    public static function autoCreateDisabled(): self
    {
        // No email in the message: it ends up in warning-level logs (R3-L24).
        return new self('No admin account exists for this identity and auto-creation is disabled for this provider.', self::REASON_AUTO_CREATE_DISABLED);
    }

    public static function noRoleResolved(): self
    {
        return new self(
            "No admin role mapping (or default role) matched this user's OIDC groups; refusing to create an admin without a role.",
            self::REASON_NO_ROLE,
        );
    }

    public static function accountMissing(): self
    {
        return new self('The account bound to this identity no longer exists.', self::REASON_ACCOUNT_MISSING);
    }

    public static function accountInactive(): self
    {
        return new self('The admin account bound to this identity is inactive.', self::REASON_ACCOUNT_INACTIVE);
    }
}
