<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\RelayStateValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Exception\RouteNotFoundException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[CoversClass(RelayStateValidator::class)]
final class RelayStateValidatorTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function offSiteTargets(): iterable
    {
        // The review's H4 corpus.
        yield 'protocol relative' => ['//evil.tld'];
        yield 'slash backslash' => ['/\\evil.tld'];
        yield 'double backslash' => ['\\\\evil.tld'];
        yield 'scheme without slashes' => ['http:evil.tld'];
        yield 'encoded tab prefix' => ['%09//evil.tld'];
        yield 'slash encoded tab slash' => ['/%09/evil.tld'];
        yield 'leading space' => [' //evil.tld'];
        yield 'absolute url with path' => ['https://x//evil.tld/p'];
        yield 'absolute url' => ['https://evil.tld/'];
        yield 'encoded slash' => ['/%2Fevil.tld'];
        yield 'encoded backslash' => ['/%5Cevil.tld'];
        yield 'javascript' => ['javascript:alert(1)'];
        yield 'relative' => ['account'];
        yield 'empty' => [''];
        yield 'trailing newline' => ["/account\n"];
        yield 'encoded trailing newline' => ['/account%0A'];
        yield 'encoded DEL' => ['/account%7F'];
    }

    #[DataProvider('offSiteTargets')]
    public function testOffSiteTargetsAreRefused(string $target): void
    {
        self::assertNull($this->validator()->resolve($target));
    }

    public function testPlainPathsAreKept(): void
    {
        self::assertSame('/account/order?page=2', $this->validator()->resolve('/account/order?page=2'));
    }

    public function testRouteNamesAreResolvedWithTheirParameters(): void
    {
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->expects(self::once())->method('generate')->with('frontend.checkout.confirm.page', ['foo' => 'bar'])->willReturn('/checkout/confirm?foo=bar');

        self::assertSame('/checkout/confirm?foo=bar', (new RelayStateValidator($router))->resolve('frontend.checkout.confirm.page', '{"foo":"bar","nested":{"x":1}}'));
    }

    public function testOnlyStorefrontRoutesAndKnownOnes(): void
    {
        $router = $this->createStub(UrlGeneratorInterface::class);
        $router->method('generate')->willThrowException(new RouteNotFoundException());

        self::assertNull((new RelayStateValidator($router))->resolve('frontend.does.not.exist'));
        self::assertNull((new RelayStateValidator($router))->resolve('api.oauth.token'));
    }

    private function validator(): RelayStateValidator
    {
        return new RelayStateValidator($this->createStub(UrlGeneratorInterface::class));
    }
}
