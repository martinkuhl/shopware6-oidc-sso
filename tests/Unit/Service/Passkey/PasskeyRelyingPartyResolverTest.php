<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyRelyingPartyResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainEntity;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SalesChannel\SalesChannelEntity;

#[CoversClass(PasskeyRelyingPartyResolver::class)]
final class PasskeyRelyingPartyResolverTest extends TestCase
{
    public function testAdministrationUsesTheAppUrlNotTheRequestHost(): void
    {
        $rp = $this->resolver('https://Shop.Example:8443/some/path')->forAdministration();

        self::assertSame('shop.example', $rp->id);
        self::assertSame(['https://shop.example:8443'], $rp->origins);
    }

    public function testConfiguredRpIdKeepsOnlyOriginsItCovers(): void
    {
        $config = $this->createStub(PasskeyConfig::class);
        $config->method('getAdminRpId')->willReturn('example.com');
        $config->method('getRpName')->willReturn('Shop');

        $rp = (new PasskeyRelyingPartyResolver($config, 'https://admin.example.com'))->forAdministration();

        self::assertSame('example.com', $rp->id);
        self::assertSame(['https://admin.example.com'], $rp->origins);

        $mismatch = (new PasskeyRelyingPartyResolver($config, 'https://other.test'))->forAdministration();
        self::assertSame([], $mismatch->origins, 'an origin outside the RP ID can never be used');
    }

    public function testOriginNormalisation(): void
    {
        self::assertSame('https://shop.example', PasskeyRelyingPartyResolver::origin('https://SHOP.example/path?x'));
        self::assertNull(PasskeyRelyingPartyResolver::origin('javascript:alert(1)'));
        self::assertNull(PasskeyRelyingPartyResolver::origin('/relative'));
    }

    public function testSalesChannelOriginsComeFromTheContextDomains(): void
    {
        $domains = new SalesChannelDomainCollection();

        foreach (['d1' => 'https://shop.example/de', 'd2' => 'https://shop.example/en', 'd3' => 'https://other.test'] as $id => $url) {
            $domain = new SalesChannelDomainEntity();
            $domain->setId($id);
            $domain->setUrl($url);
            $domains->add($domain);
        }

        $salesChannel = new SalesChannelEntity();
        $salesChannel->setDomains($domains);
        $salesChannel->setTranslated(['name' => 'Shop']);

        $context = $this->createStub(SalesChannelContext::class);
        $context->method('getSalesChannel')->willReturn($salesChannel);
        $context->method('getSalesChannelId')->willReturn('sc');
        $context->method('getDomainId')->willReturn('d2');

        $config = $this->createStub(PasskeyConfig::class);
        $config->method('getRpId')->willReturnArgument(0);
        $config->method('getRpName')->willReturnArgument(0);

        // No database query: the domains core loaded into the context (R3-L19).
        $rp = (new PasskeyRelyingPartyResolver($config, 'https://admin.example'))->forSalesChannel($context);

        self::assertSame('shop.example', $rp->id);
        self::assertSame(['https://shop.example'], $rp->origins);
    }

    private function resolver(string $appUrl): PasskeyRelyingPartyResolver
    {
        $config = $this->createStub(PasskeyConfig::class);
        $config->method('getAdminRpId')->willReturnArgument(0);
        $config->method('getRpName')->willReturnArgument(0);

        return new PasskeyRelyingPartyResolver($config, $appUrl);
    }
}
