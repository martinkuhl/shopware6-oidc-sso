<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthTimeValidator;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\FreshLoginNotConfirmedException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthTimeValidator::class)]
final class AuthTimeValidatorTest extends TestCase
{
    public function testALoginAfterTheRoundTripStartedIsFresh(): void
    {
        $this->expectNotToPerformAssertions();

        AuthTimeValidator::assertFresh($this->callbackResult(time()));
        AuthTimeValidator::assertFresh($this->callbackResult(time() - 100 - AuthTimeValidator::LEEWAY_SECONDS + 1));
    }

    public function testAnOldIdpSessionIsRefused(): void
    {
        $this->expectException(InvalidStateException::class);

        AuthTimeValidator::assertFresh($this->callbackResult(time() - 3600));
    }

    public function testAMissingAuthTimeIsRefused(): void
    {
        $this->expectException(FreshLoginNotConfirmedException::class);

        AuthTimeValidator::assertFresh($this->callbackResult(null));
    }

    /**
     * R8-L32: auth_time is asked for as an essential claim, but only where the
     * IdP supports the `claims` parameter; never max_age (Authelia, 2dabbd4).
     */
    public function testFreshLoginParametersAskForAuthTimeOnlyWhereSupported(): void
    {
        $provider = new Sw6OidcProviderEntity();

        self::assertSame(['prompt' => 'login'], AuthTimeValidator::freshLoginParameters($provider));

        $provider->setClaimsParameterSupported(true);
        $parameters = AuthTimeValidator::freshLoginParameters($provider);

        self::assertSame('login', $parameters['prompt']);
        self::assertArrayNotHasKey('max_age', $parameters);
        self::assertSame(['id_token' => ['auth_time' => ['essential' => true]]], json_decode($parameters['claims'], true));
    }

    private function callbackResult(?int $authTime): OidcCallbackResult
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('p0000000000000000000000000000001');
        $claims = ['sub' => 'subject-1'] + ($authTime !== null ? ['auth_time' => $authTime] : []);

        return new OidcCallbackResult(
            $provider,
            new AuthorizationFlowContext($provider->getId(), 'customer', '', 'v', 'S256', 'n', AuthorizationFlowContext::PURPOSE_REAUTH, 'c0000000000000000000000000000001', time() - 100),
            new MappedProfile('customer@example.com'),
            ['access_token' => 'at'],
            $claims,
            $claims,
        );
    }
}
