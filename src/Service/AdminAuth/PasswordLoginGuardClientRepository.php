<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * Decorates core's OAuth ClientRepository: while Administration password
 * login is disabled, a *user* access key (SWUA…) is a password in all but
 * name, so it can't authenticate either — however the token request spells
 * `client_id` (padded, empty plus Basic auth, …), and also for core's MCP
 * endpoint, which authenticates through the same repository (R3-M20).
 * Integration keys are unaffected. SW6OIDC_ALLOW_USER_ACCESS_KEYS=1 opts out.
 *
 * AdminPasswordLoginGuardSubscriber only adds a friendlier 403 in front.
 */
class PasswordLoginGuardClientRepository implements ClientRepositoryInterface
{
    /** AccessKeyHelper's prefix for keys of origin `user`. */
    public const USER_ACCESS_KEY_PREFIX = 'SWUA';

    public function __construct(
        private readonly ClientRepositoryInterface $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
        private readonly LoggerInterface $logger,
        private readonly bool $allowUserAccessKeys = false,
    ) {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if ($this->refuses($clientIdentifier)) {
            return null;
        }

        return $this->decorated->getClientEntity($clientIdentifier);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        if ($this->refuses($clientIdentifier)) {
            return false;
        }

        return $this->decorated->validateClient($clientIdentifier, $clientSecret, $grantType);
    }

    public static function isUserAccessKey(string $clientIdentifier): bool
    {
        return str_starts_with(strtoupper(trim($clientIdentifier)), self::USER_ACCESS_KEY_PREFIX);
    }

    private function refuses(string $clientIdentifier): bool
    {
        if ($this->allowUserAccessKeys || !self::isUserAccessKey($clientIdentifier)) {
            return false;
        }

        if (!$this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Admin->value, Context::createDefaultContext())) {
            return false;
        }

        $this->logger->notice('sw6oidc: user access key refused, Administration password login is disabled.');

        return true;
    }
}
