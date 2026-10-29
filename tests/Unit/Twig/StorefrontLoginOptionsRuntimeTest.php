<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Twig;

use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use MartinKuhl\Sw6Oidc\Twig\StorefrontLoginOptionsExtension;
use MartinKuhl\Sw6Oidc\Twig\StorefrontLoginOptionsRuntime;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Contracts\Translation\TranslatorInterface;

#[CoversClass(StorefrontLoginOptionsRuntime::class)]
#[CoversClass(StorefrontLoginOptionsExtension::class)]
final class StorefrontLoginOptionsRuntimeTest extends TestCase
{
    public function testLookupsAreMemoisedPerRequest(): void
    {
        $resolver = $this->createMock(ProviderResolver::class);
        $resolver->expects(self::exactly(2))->method('getVisibleProviders')->willReturn([]);
        $policy = $this->createMock(PasswordLoginPolicy::class);
        $policy->expects(self::exactly(2))->method('isPasswordLoginDisabled')->willReturn(false);

        $runtime = new StorefrontLoginOptionsRuntime(
            $resolver,
            $this->createStub(PasskeyConfig::class),
            $this->createStub(PasskeyCredentialRepository::class),
            $this->createStub(TranslatorInterface::class),
            $policy,
            $this->createStub(UserProviderBindingService::class),
        );
        $context = $this->createStub(SalesChannelContext::class);
        $context->method('getSalesChannelId')->willReturn('sc');
        $context->method('getLanguageId')->willReturn('lang');
        $context->method('getContext')->willReturn(Context::createDefaultContext());

        // The login form, header and account pages ask several times per request (R3-L47).
        $runtime->getSsoProviders($context);
        $runtime->getSsoProviders($context);
        $runtime->isPasswordLoginDisabled($context);
        $runtime->isPasswordLoginDisabled($context);

        $runtime->reset();
        $runtime->getSsoProviders($context);
        $runtime->isPasswordLoginDisabled($context);
    }

    public function testTheExtensionOnlyDeclaresFunctions(): void
    {
        // No services in the extension: Twig builds the runtime only on use (R3-L46).
        $names = array_map(static fn ($function): string => $function->getName(), (new StorefrontLoginOptionsExtension())->getFunctions());

        self::assertContains('sw6oidc_storefront_sso_providers', $names);
        self::assertCount(5, $names);
    }
}
