<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;

/**
 * Thrown by Sw6OidcAccessControlEvaluator when a claims-based access-control
 * rule rejects the login. Carries the rule's admin-configured message (null =
 * the callers show their generic "access denied" text).
 */
class AccessControlDeniedException extends Sw6OidcException
{
    protected const STATUS_CODE = 403;
    protected const ERROR_CODE = 'SW6OIDC_ACCESS_DENIED';

    public function __construct(
        public readonly string $ruleId,
        public readonly string $claimKey,
        public readonly ?string $userMessage,
    ) {
        parent::__construct(sprintf('Login denied by access-control rule %s (claim "%s").', $ruleId, $claimKey));
    }

    /**
     * The configured message as plain text (tags stripped, whitespace
     * collapsed, capped), or null when none is configured.
     */
    public function getDisplayMessage(): ?string
    {
        if ($this->userMessage === null) {
            return null;
        }

        $message = trim((string) preg_replace('/\s+/u', ' ', strip_tags($this->userMessage)));

        return $message === '' ? null : mb_substr($message, 0, 500);
    }
}
