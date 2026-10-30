<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyLoginPolicy;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;

/**
 * Offboarding at the IdP (deactivating the provider) also stops the passkey
 * logins of the accounts connected to it — when the shop asks for it.
 */
#[CoversClass(PasskeyLoginPolicy::class)]
final class PasskeyLoginPolicyTest extends TestCase
{
    public function testOnlyActiveProvidersKeepPasskeyLoginsOfTheirAccountsWhenRequired(): void
    {
        $context = Context::createDefaultContext();

        self::assertTrue($this->policy(required: false, boundTo: 'p1', active: false)->allows('admin', 'u1', $context), 'policy off');
        self::assertTrue($this->policy(required: true, boundTo: null, active: false)->allows('admin', 'u1', $context), 'no SSO binding');
        self::assertTrue($this->policy(required: true, boundTo: 'p1', active: true)->allows('admin', 'u1', $context));
        self::assertFalse($this->policy(required: true, boundTo: 'p1', active: false)->allows('admin', 'u1', $context));
    }

    private function policy(bool $required, ?string $boundTo, bool $active): PasskeyLoginPolicy
    {
        $config = $this->createStub(PasskeyConfig::class);
        $config->method('requiresActiveSso')->willReturn($required);
        $bindings = $this->createStub(UserProviderBindingService::class);
        $bindings->method('getBoundProviderId')->willReturn($boundTo);
        $providers = $this->createStub(ProviderResolver::class);

        if ($active) {
            $providers->method('getActiveById')->willReturn(new Sw6OidcProviderEntity());
        } else {
            $providers->method('getActiveById')->willThrowException(new ProviderNotFoundException('inactive'));
        }

        return new PasskeyLoginPolicy($config, $bindings, $providers);
    }
}
