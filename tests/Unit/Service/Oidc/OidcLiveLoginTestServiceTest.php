<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsNormalizer;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcLiveLoginTestService;
use MartinKuhl\Sw6Oidc\Service\Oidc\TokenExchangeService;
use MartinKuhl\Sw6Oidc\Service\Oidc\UserInfoService;
use PHPUnit\Framework\Attributes\CoversClass;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcAccessControlEvaluator;
use PHPUnit\Framework\TestCase;

/**
 * These tests exist specifically to lock in the "never provisions a real
 * account" safety property: every scenario below asserts on the returned
 * report only, never touching AdminProvisioningService/CustomerProvisioningService
 * (which this service must never call in the first place).
 */
#[CoversClass(OidcLiveLoginTestService::class)]
final class OidcLiveLoginTestServiceTest extends TestCase
{
    public function testReturnsFailWhenTokenExchangeThrows(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willThrowException(new \RuntimeException('token endpoint unreachable'));

        $service = $this->buildService($tokenExchangeService);

        $result = $service->run($this->buildProvider(), 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('fail', $result['status']);
        self::assertSame('token_exchange', $result['steps'][0]['id']);
        self::assertSame('fail', $result['steps'][0]['status']);
        self::assertSame([], $result['claims']);
    }

    public function testReturnsFailWhenTheTokenResponseHasNoAccessToken(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn([]);

        $service = $this->buildService($tokenExchangeService);

        $result = $service->run($this->buildProvider(), 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('fail', $result['status']);
        self::assertSame('fail', $result['steps'][0]['status']);
    }

    public function testHappyPathVerifiesTheIdTokenAndFetchesUserinfo(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at', 'id_token' => 'idt']);

        $jwtVerifier = $this->createMock(JwtVerifier::class);
        $jwtVerifier->method('verify')->willReturn(['sub' => '123']);

        $userInfoService = $this->createMock(UserInfoService::class);
        $userInfoService->method('fetchClaims')->willReturn(['sub' => '123', 'email' => 'alice@example.com']);

        $claimsNormalizer = $this->createMock(ClaimsNormalizer::class);
        $claimsNormalizer->method('flatten')->willReturn(['sub' => '123', 'email' => 'alice@example.com']);

        $service = $this->buildService($tokenExchangeService, $jwtVerifier, $userInfoService, $claimsNormalizer);

        $provider = $this->buildProvider();
        $provider->setUserInfoEndpoint('https://idp.example/userinfo');

        $result = $service->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('pass', $result['status']);
        self::assertSame(['sub' => '123', 'email' => 'alice@example.com'], $result['claims']);

        foreach ($result['steps'] as $step) {
            self::assertContains($step['status'], ['pass', 'skipped'], $step['id']);
        }
    }

    public function testAMissingIdTokenFailsWhenTheOpenidScopeIsRequested(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at']);

        $provider = $this->buildProvider();
        $provider->setScope('openid email');

        $result = $this->buildService($tokenExchangeService)->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('fail', $result['status'], 'a real login refuses this');
    }

    public function testUserinfoForAnotherSubjectFails(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at', 'id_token' => 'idt']);
        $jwtVerifier = $this->createMock(JwtVerifier::class);
        $jwtVerifier->method('verify')->willReturn(['sub' => '123']);
        $userInfoService = $this->createMock(UserInfoService::class);
        $userInfoService->method('fetchClaims')->willReturn(['sub' => 'someone-else']);

        $provider = $this->buildProvider();
        $provider->setUserInfoEndpoint('https://idp.example/userinfo');

        $result = $this->buildService($tokenExchangeService, $jwtVerifier, $userInfoService, new ClaimsNormalizer())->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('fail', $result['status']);
        self::assertContains('claims', array_column($result['steps'], 'id'));
    }

    public function testGroupsAreNormalizedLikeARealLogin(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at', 'id_token' => 'idt']);
        $jwtVerifier = $this->createMock(JwtVerifier::class);
        $jwtVerifier->method('verify')->willReturn(['sub' => '123', 'roles' => ['Admins' => ['orgId' => '1'], 'Staff' => ['orgId' => '1']]]);

        $provider = $this->buildProvider();
        $provider->setGroupAttribute('roles');

        $result = $this->buildService($tokenExchangeService, $jwtVerifier, null, new ClaimsNormalizer())->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        $groups = array_values(array_filter($result['steps'], static fn (array $step): bool => $step['id'] === 'groups'))[0];
        self::assertSame(['count' => 2], $groups['messageParams'] ?? null);
    }

    public function testSkipsIdTokenVerificationWhenNoIdTokenIsPresent(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at']);

        $jwtVerifier = $this->createMock(JwtVerifier::class);
        $jwtVerifier->expects(self::never())->method('verify');

        $service = $this->buildService($tokenExchangeService, $jwtVerifier);

        $provider = $this->buildProvider();
        $provider->setScope('profile email');

        $result = $service->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        $idTokenStep = array_values(array_filter($result['steps'], static fn (array $step): bool => $step['id'] === 'id_token_verification'))[0];
        self::assertSame('skipped', $idTokenStep['status']);
    }

    public function testSkipsUserinfoFetchWhenNoUserInfoEndpointIsConfigured(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at']);

        $userInfoService = $this->createMock(UserInfoService::class);
        $userInfoService->expects(self::never())->method('fetchClaims');

        $service = $this->buildService($tokenExchangeService, null, $userInfoService);

        $provider = $this->buildProvider();
        $provider->setUserInfoEndpoint(null);

        $result = $service->run($provider, 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        $userInfoStep = array_values(array_filter($result['steps'], static fn (array $step): bool => $step['id'] === 'userinfo_fetch'))[0];
        self::assertSame('skipped', $userInfoStep['status']);
    }

    public function testOverallStatusIsFailWhenIdTokenVerificationFailsEvenIfOtherStepsSucceed(): void
    {
        $tokenExchangeService = $this->createMock(TokenExchangeService::class);
        $tokenExchangeService->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at', 'id_token' => 'idt']);

        $jwtVerifier = $this->createMock(JwtVerifier::class);
        $jwtVerifier->method('verify')->willThrowException(new InvalidJwtException('signature mismatch'));

        $service = $this->buildService($tokenExchangeService, $jwtVerifier);

        $result = $service->run($this->buildProvider(), 'code', 'verifier', 'https://shop.example/callback', 'nonce');

        self::assertSame('fail', $result['status']);
    }

    private function buildService(
        ?TokenExchangeService $tokenExchangeService = null,
        ?JwtVerifier $jwtVerifier = null,
        ?UserInfoService $userInfoService = null,
        ?ClaimsNormalizer $claimsNormalizer = null,
    ): OidcLiveLoginTestService {
        return new OidcLiveLoginTestService(
            $tokenExchangeService ?? $this->createMock(TokenExchangeService::class),
            $userInfoService ?? $this->createMock(UserInfoService::class),
            $jwtVerifier ?? $this->createMock(JwtVerifier::class),
            $claimsNormalizer ?? $this->createMock(ClaimsNormalizer::class),
            $this->createMock(Sw6OidcAccessControlEvaluator::class),
        );
    }

    private function buildProvider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId('provider-1');
        $provider->setAppName('test-provider');
        $provider->setClientId('client-1');
        $provider->setClientSecret('secret');
        $provider->setJwksEndpoint('https://idp.example/jwks');
        $provider->setIssuer('https://idp.example');
        $provider->setJwksCacheTtl(3600);
        $provider->setHttpTimeout(10);
        $provider->setUserInfoEndpoint(null);

        return $provider;
    }
}
