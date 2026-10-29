<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleEntity;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsNormalizer;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackProcessor;
use MartinKuhl\Sw6Oidc\Service\Oidc\TokenExchangeService;
use MartinKuhl\Sw6Oidc\Service\Oidc\UserInfoService;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeMapper;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
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

#[CoversClass(OidcCallbackProcessor::class)]
final class OidcCallbackProcessorAccessControlTest extends TestCase
{
    public function testDeniedLoginNeverReachesAttributeMapping(): void
    {
        $mapper = $this->createMock(AttributeMapper::class);
        $mapper->expects(self::never())->method('map');

        $this->expectException(AccessControlDeniedException::class);

        $this->process($mapper, $this->rule('groups', 'contains', 'staff'), ['email' => 'a@example.com', 'groups' => ['guests']]);
    }

    public function testPassingRulesContinueToAttributeMapping(): void
    {
        $mapper = $this->createMock(AttributeMapper::class);
        $mapper->expects(self::once())->method('map')
            ->with(self::anything(), self::callback(static fn (array $claims): bool => ($claims['groups.0'] ?? null) === 'staff'))
            ->willReturn(new MappedProfile('a@example.com'));

        $result = $this->process($mapper, $this->rule('groups', 'contains', 'Staff'), ['email' => 'a@example.com', 'groups' => ['staff']]);

        self::assertSame('a@example.com', $result->profile->email);
    }

    /**
     * @param array<string, mixed> $userInfoClaims
     */
    private function process(AttributeMapper $mapper, Sw6OidcAccessControlRuleEntity $rule, array $userInfoClaims): \MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackResult
    {
        $provider = new Sw6OidcProviderEntity();
        // Without the openid scope the flow may rely on userinfo alone.
        $provider->assign(['id' => 'provider-1', 'groupAttribute' => 'groups', 'scope' => 'email profile']);

        $resolver = $this->createStub(ProviderResolver::class);
        $resolver->method('getActiveById')->willReturn($provider);

        $tokens = $this->createStub(TokenExchangeService::class);
        $tokens->method('exchangeCodeForTokens')->willReturn(['access_token' => 'at']);

        $userInfo = $this->createStub(UserInfoService::class);
        $userInfo->method('fetchClaims')->willReturn(['sub' => 'subject-1', ...$userInfoClaims]);

        $rules = $this->createStub(EntityRepository::class);
        $rules->method('search')->willReturnCallback(static fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
            Sw6OidcAccessControlRuleDefinition::ENTITY_NAME,
            1,
            new Sw6OidcAccessControlRuleCollection([$rule]),
            null,
            $criteria,
            $context,
        ));

        $security = new OidcSecurityHelper(new InMemoryAtomicCache(), new BrowserBinding(new RequestStack()));
        $state = $security->beginAuthorizationRequest('provider-1', 'customer', '', 'S256')['state'];

        $processor = new OidcCallbackProcessor(
            $resolver,
            $security,
            $tokens,
            $userInfo,
            $this->createStub(JwtVerifier::class),
            new ClaimsNormalizer(),
            $mapper,
            new NullLogger(),
            new Sw6OidcAccessControlEvaluator($rules, new NullLogger()),
        );

        return $processor->process('code', $state, 'https://shop.example/sw6oidc/callback', 'customer', Context::createDefaultContext());
    }

    private function rule(string $claimKey, string $operator, string $value): Sw6OidcAccessControlRuleEntity
    {
        $rule = new Sw6OidcAccessControlRuleEntity();
        $rule->assign(['id' => 'rule-1', 'providerId' => 'provider-1', 'claimKey' => $claimKey, 'operator' => $operator, 'value' => $value]);

        return $rule;
    }
}
