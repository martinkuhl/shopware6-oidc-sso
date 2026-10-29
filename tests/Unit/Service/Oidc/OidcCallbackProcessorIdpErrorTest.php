<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsNormalizer;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcCallbackProcessor;
use MartinKuhl\Sw6Oidc\Service\Oidc\TokenExchangeService;
use MartinKuhl\Sw6Oidc\Service\Oidc\UserInfoService;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeMapper;
use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcAccessControlEvaluator;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * IdP error responses (`?error=…`) end their flow, and only an error that
 * names no flow of this browser is a possible forgery (R4-L4).
 */
#[CoversClass(OidcCallbackProcessor::class)]
final class OidcCallbackProcessorIdpErrorTest extends TestCase
{
    private OidcSecurityHelper $security;

    private OidcCallbackProcessor $processor;

    protected function setUp(): void
    {
        $this->security = new OidcSecurityHelper(new InMemoryAtomicCache(), new BrowserBinding(new RequestStack()));
        $this->processor = new OidcCallbackProcessor(
            $this->createStub(ProviderResolver::class),
            $this->security,
            $this->createStub(TokenExchangeService::class),
            $this->createStub(UserInfoService::class),
            $this->createStub(JwtVerifier::class),
            $this->createStub(ClaimsNormalizer::class),
            $this->createStub(AttributeMapper::class),
            new NullLogger(),
            $this->createStub(Sw6OidcAccessControlEvaluator::class),
        );
    }

    public function testErrorForAKnownFlowEndsThatFlow(): void
    {
        $state = $this->security->beginAuthorizationRequest('provider-1', 'customer', '', 'S256')['state'];

        $flow = $this->processor->abortFlowWithIdpError($state, 'customer');

        self::assertNotNull($flow);
        self::assertSame('provider-1', $flow->providerId);
        // Consumed: the same state can't be used again.
        self::assertNull($this->processor->abortFlowWithIdpError($state, 'customer'));
    }

    public function testErrorWithoutAFlowOfThisLoginTypeIsUnattributed(): void
    {
        $state = $this->security->beginAuthorizationRequest('provider-1', 'customer', '', 'S256')['state'];

        self::assertNull($this->processor->abortFlowWithIdpError($state, 'admin'));
        self::assertNull($this->processor->abortFlowWithIdpError('unknown', 'customer'));
        self::assertNull($this->processor->abortFlowWithIdpError(null, 'customer'));
    }

    public function testLogContextIsCutShortAndIgnoresNonStrings(): void
    {
        $context = OidcCallbackProcessor::idpErrorLogContext(str_repeat('e', 500), str_repeat('d', 8192));

        self::assertSame(64, mb_strlen($context['error']));
        self::assertSame(200, mb_strlen($context['error_description']));
        self::assertSame(['error' => '', 'error_description' => ''], OidcCallbackProcessor::idpErrorLogContext(['x'], 42));
    }
}
