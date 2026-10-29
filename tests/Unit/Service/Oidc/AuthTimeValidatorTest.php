<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthTimeValidator;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
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
        $this->expectException(InvalidStateException::class);

        AuthTimeValidator::assertFresh($this->callbackResult(null));
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
