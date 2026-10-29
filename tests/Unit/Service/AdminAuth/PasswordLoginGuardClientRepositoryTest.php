<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\PasswordLoginGuardClientRepository;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/**
 * R3-M20: in SSO-only mode a user access key is refused where League asks
 * for the client, however the request spelled `client_id`.
 */
#[CoversClass(PasswordLoginGuardClientRepository::class)]
final class PasswordLoginGuardClientRepositoryTest extends TestCase
{
    public function testUserAccessKeysAreRefusedInSsoOnlyMode(): void
    {
        $repository = $this->repository(policyOn: true);

        foreach (['SWUAABCDEF', ' SWUAABCDEF', 'swuaabcdef'] as $clientId) {
            self::assertNull($repository->getClientEntity($clientId), $clientId);
            self::assertFalse($repository->validateClient($clientId, 'secret', 'client_credentials'), $clientId);
        }
    }

    public function testIntegrationKeysAndTheAdministrationClientAreUnaffected(): void
    {
        $repository = $this->repository(policyOn: true);

        self::assertNotNull($repository->getClientEntity('SWIAABCDEF'));
        self::assertNotNull($repository->getClientEntity('administration'));
        self::assertTrue($repository->validateClient('SWIAABCDEF', 'secret', 'client_credentials'));
    }

    public function testUserAccessKeysWorkWithoutSsoOnlyModeOrWithTheOptOut(): void
    {
        self::assertNotNull($this->repository(policyOn: false)->getClientEntity('SWUAABCDEF'));
        self::assertNotNull($this->repository(policyOn: true, allowUserAccessKeys: true)->getClientEntity('SWUAABCDEF'));
    }

    private function repository(bool $policyOn, bool $allowUserAccessKeys = false): PasswordLoginGuardClientRepository
    {
        $inner = $this->createStub(ClientRepositoryInterface::class);
        $inner->method('getClientEntity')->willReturn($this->createStub(ClientEntityInterface::class));
        $inner->method('validateClient')->willReturn(true);

        $policy = $this->createStub(PasswordLoginPolicy::class);
        $policy->method('isPasswordLoginDisabled')->willReturn($policyOn);

        return new PasswordLoginGuardClientRepository($inner, $policy, new NullLogger(), $allowUserAccessKeys);
    }
}
