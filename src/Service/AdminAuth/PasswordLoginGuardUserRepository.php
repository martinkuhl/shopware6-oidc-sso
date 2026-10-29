<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\AdminAuth;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * Decorates core's OAuth UserRepository — the one place League's password
 * grant asks "are these credentials valid?". While disable_non_oidc_admin_login
 * is on, no username/password pair is valid, however the token request was
 * encoded (form, application/json, application/x-json, …): the grant fails
 * with invalid_grant exactly like wrong credentials.
 *
 * AdminPasswordLoginGuardSubscriber only adds a friendlier 403 in front of
 * this; the decorator is what actually enforces the policy.
 */
class PasswordLoginGuardUserRepository implements UserRepositoryInterface
{
    public function __construct(
        private readonly UserRepositoryInterface $decorated,
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function getUserEntityByUserCredentials(
        string $username,
        #[\SensitiveParameter]
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity,
    ): ?UserEntityInterface {
        if ($this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Admin->value, Context::createDefaultContext())) {
            $this->logger->notice('sw6oidc: Administration password login refused, password login is disabled.', [
                'grantType' => $grantType,
            ]);

            return null;
        }

        return $this->decorated->getUserEntityByUserCredentials($username, $password, $grantType, $clientEntity);
    }
}
