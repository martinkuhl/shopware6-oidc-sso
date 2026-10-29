<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\StepUpService;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthorizationRequestBuilder;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyAuthenticationService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingPartyResolver;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;

#[CoversClass(StepUpService::class)]
final class StepUpServiceTest extends TestCase
{
    private const ADMIN = 'a0000000000000000000000000000001';

    private string $subjectOwner = self::ADMIN;

    public function testFreshReauthenticationOfTheSameAdminYieldsASingleUseNonce(): void
    {
        $service = $this->service();
        $nonce = $service->completeOidc($this->callbackResult(time()), Context::createDefaultContext());

        self::assertFalse($service->redeemNonce($nonce, 'someone-else'), 'bound to the admin who started it');

        $nonce = $service->completeOidc($this->callbackResult(time()), Context::createDefaultContext());
        self::assertTrue($service->redeemNonce($nonce, self::ADMIN));
        self::assertFalse($service->redeemNonce($nonce, self::ADMIN), 'single use');
    }

    public function testStaleIdpSessionIsRefused(): void
    {
        $this->expectException(InvalidStateException::class);

        // The IdP reused a login from an hour ago instead of prompting.
        $this->service()->completeOidc($this->callbackResult(time() - 3600), Context::createDefaultContext());
    }

    public function testMissingAuthTimeIsRefused(): void
    {
        $this->expectException(InvalidStateException::class);

        $this->service()->completeOidc($this->callbackResult(null), Context::createDefaultContext());
    }

    public function testAnotherIdentityIsRefused(): void
    {
        $this->subjectOwner = 'b0000000000000000000000000000002';

        $this->expectException(InvalidStateException::class);

        $this->service()->completeOidc($this->callbackResult(time()), Context::createDefaultContext());
    }

    public function testOidcStepUpAsksTheIdpForAFreshLogin(): void
    {
        $builder = $this->createMock(AuthorizationRequestBuilder::class);
        $builder->expects(self::once())->method('build')
            ->with(
                self::isInstanceOf(Sw6OidcProviderEntity::class),
                'admin',
                '',
                'https://shop.example/cb',
                AuthorizationFlowContext::PURPOSE_STEP_UP,
                self::ADMIN,
                ['prompt' => 'login'],
            )
            ->willReturn('https://idp.example/authorize?x');

        self::assertSame('https://idp.example/authorize?x', $this->service($builder)->oidcAuthorizeUrl(self::ADMIN, 'https://shop.example/cb', Context::createDefaultContext()));
    }

    private function service(?AuthorizationRequestBuilder $builder = null): StepUpService
    {
        $bindings = $this->createStub(UserProviderBindingService::class);
        $bindings->method('findUserIdBySubject')->willReturnCallback(fn (): string => $this->subjectOwner);
        $bindings->method('getBoundProviderId')->willReturn('p0000000000000000000000000000001');

        $resolver = $this->createStub(ProviderResolver::class);
        $resolver->method('getActiveById')->willReturn(new Sw6OidcProviderEntity());

        return new StepUpService(
            $bindings,
            $resolver,
            $builder ?? $this->createStub(AuthorizationRequestBuilder::class),
            new InMemoryAtomicCache(),
            $this->createStub(PasskeyAuthenticationService::class),
            $this->createStub(PasskeyCredentialRepository::class),
            $this->createStub(PasskeyRelyingPartyResolver::class),
            new NullLogger(),
        );
    }

    private function callbackResult(?int $authTime): OidcCallbackResult
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('p0000000000000000000000000000001');

        $claims = ['sub' => 'subject-1', 'iss' => 'https://idp.example'];

        if ($authTime !== null) {
            $claims['auth_time'] = $authTime;
        }

        return new OidcCallbackResult(
            $provider,
            new AuthorizationFlowContext($provider->getId(), 'admin', '', 'v', 'S256', 'n', AuthorizationFlowContext::PURPOSE_STEP_UP, self::ADMIN, time() - 5),
            new MappedProfile('admin@example.com'),
            ['access_token' => 'at'],
            $claims,
            $claims,
        );
    }
}
