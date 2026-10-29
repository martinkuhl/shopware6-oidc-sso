<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsNormalizer;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackProcessor;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult;
use MartinKuhl\Sw6Oidc\Service\Oidc\TokenExchangeService;
use MartinKuhl\Sw6Oidc\Service\Oidc\UserInfoService;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeMapper;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcAccessControlEvaluator;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RequestStack;
use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;

/**
 * Identity-defining rules of the shared callback pipeline: the login type a
 * flow was started for, the required id_token, and which source wins for
 * `sub`/`email`/`email_verified`.
 */
#[CoversClass(OidcCallbackProcessor::class)]
#[CoversClass(OidcCallbackResult::class)]
final class OidcCallbackProcessorIdentityTest extends TestCase
{
    public function testFlowStartedForTheStorefrontIsRejectedAtTheAdminCallback(): void
    {
        $this->expectException(InvalidStateException::class);

        $this->process(flowLoginType: 'customer', callbackLoginType: 'admin', tokens: ['access_token' => 'at', 'id_token' => 'x'], idTokenClaims: ['sub' => 's']);
    }

    public function testOpenIdScopeWithoutIdTokenIsRejected(): void
    {
        $this->expectException(InvalidStateException::class);
        $this->expectExceptionMessage('id_token');

        $this->process(tokens: ['access_token' => 'at'], userInfoClaims: ['sub' => 's', 'email' => 'a@example.com']);
    }

    public function testUserinfoForAnotherSubjectIsRejected(): void
    {
        $this->expectException(InvalidStateException::class);
        $this->expectExceptionMessage('different subject');

        $this->process(idTokenClaims: ['sub' => 'alice'], userInfoClaims: ['sub' => 'mallory', 'email' => 'm@example.com']);
    }

    public function testIdTokenWinsForIdentityClaims(): void
    {
        $result = $this->process(
            idTokenClaims: ['sub' => 'alice', 'email' => 'alice@example.com', 'email_verified' => false, 'iss' => 'https://idp.example.com'],
            userInfoClaims: ['sub' => 'alice', 'email' => 'bob@example.com', 'email_verified' => true, 'name' => 'Alice'],
        );

        self::assertSame('alice@example.com', $result->claims['email']);
        self::assertFalse($result->claims['email_verified']);
        self::assertSame('Alice', $result->claims['name']);
        self::assertFalse($result->identity()->emailVerified);
        self::assertSame('alice', $result->identity()->subject);
        self::assertSame('https://idp.example.com', $result->identity()->issuer);
    }

    public function testVerifiedEmailOnlyCountsForTheMappedStandardEmailClaim(): void
    {
        $verified = $this->process(idTokenClaims: ['sub' => 'a', 'email' => 'A@Example.com', 'email_verified' => 'true']);
        self::assertTrue($verified->emailVerified());

        $customClaim = $this->process(idTokenClaims: ['sub' => 'a', 'email' => 'other@example.com', 'email_verified' => true]);
        self::assertFalse($customClaim->emailVerified());
    }

    public function testMissingSubjectIsRejected(): void
    {
        $this->expectException(InvalidStateException::class);

        $this->process(scope: 'email', tokens: ['access_token' => 'at'], userInfoClaims: ['email' => 'a@example.com']);
    }

    /**
     * @param array<string, mixed> $tokens
     * @param array<string, mixed> $idTokenClaims
     * @param array<string, mixed> $userInfoClaims
     */
    private function process(
        string $flowLoginType = 'customer',
        string $callbackLoginType = 'customer',
        string $scope = 'openid email',
        array $tokens = ['access_token' => 'at', 'id_token' => 'header.payload.sig'],
        array $idTokenClaims = [],
        array $userInfoClaims = [],
    ): OidcCallbackResult {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign(['id' => 'provider-1', 'groupAttribute' => 'groups', 'scope' => $scope, 'clientId' => 'client', 'issuer' => 'https://idp.example.com']);

        $resolver = $this->createStub(ProviderResolver::class);
        $resolver->method('getActiveById')->willReturn($provider);

        $tokenService = $this->createStub(TokenExchangeService::class);
        $tokenService->method('exchangeCodeForTokens')->willReturn($tokens);

        $userInfo = $this->createStub(UserInfoService::class);
        $userInfo->method('fetchClaims')->willReturn($userInfoClaims);

        $jwt = $this->createStub(JwtVerifier::class);
        $jwt->method('verify')->willReturn($idTokenClaims);

        $rules = $this->createStub(EntityRepository::class);
        $rules->method('search')->willReturnCallback(static fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
            Sw6OidcAccessControlRuleDefinition::ENTITY_NAME,
            0,
            new Sw6OidcAccessControlRuleCollection([]),
            null,
            $criteria,
            $context,
        ));

        $mapper = $this->createStub(AttributeMapper::class);
        $mapper->method('map')->willReturn(new MappedProfile('a@example.com'));

        $security = new OidcSecurityHelper(new InMemoryAtomicCache(), new BrowserBinding(new RequestStack()));
        $state = $security->beginAuthorizationRequest('provider-1', $flowLoginType, '', 'S256')['state'];

        $processor = new OidcCallbackProcessor(
            $resolver,
            $security,
            $tokenService,
            $userInfo,
            $jwt,
            new ClaimsNormalizer(),
            $mapper,
            new NullLogger(),
            new Sw6OidcAccessControlEvaluator($rules, new NullLogger()),
        );

        return $processor->process('code', $state, 'https://shop.example/cb', $callbackLoginType, Context::createDefaultContext());
    }
}
