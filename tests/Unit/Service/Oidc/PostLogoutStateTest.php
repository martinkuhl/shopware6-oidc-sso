<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Controller\Oidc\PostLogoutController;
use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[CoversClass(PostLogoutState::class)]
#[CoversClass(PostLogoutController::class)]
final class PostLogoutStateTest extends TestCase
{
    public function testRoundTripsBothTargets(): void
    {
        $state = new PostLogoutState('secret');

        self::assertSame('customer', $state->parse($state->create('customer')));
        self::assertSame('admin', $state->parse($state->create('admin')));
    }

    public function testRejectsForgedTamperedOrForeignStates(): void
    {
        $state = new PostLogoutState('secret');
        [$target, $random, $signature] = explode('.', $state->create('customer'));

        self::assertNull($state->parse('admin.' . $random . '.' . $signature), 'target swapped');
        self::assertNull($state->parse((new PostLogoutState('other-secret'))->create('admin')), 'other installation');
        self::assertNull($state->parse('admin:0123456789abcdef'), 'legacy unsigned format');
        self::assertNull($state->parse(null));
        self::assertNull($state->parse('a.b.c.d'));
    }

    public function testLandingSendsAdminsToTheAdministrationAndEveryoneElseToTheStorefrontLogin(): void
    {
        $state = new PostLogoutState('secret');
        $controller = new PostLogoutController($state, 'https://shop.example/admin');
        $router = $this->createStub(UrlGeneratorInterface::class);
        $router->method('generate')->willReturn('/account/login');
        $container = new Container();
        $container->set('router', $router);
        $controller->setContainer($container);

        $landing = static fn (array $query): string => $controller->landing(new Request($query))->getTargetUrl();

        self::assertSame('https://shop.example/admin/', $landing(['state' => $state->create('admin')]));
        self::assertSame('/account/login', $landing(['state' => $state->create('customer')]));
        self::assertSame('/account/login', $landing(['state' => 'admin.forged.state']));
        self::assertSame('/account/login', $landing([]));
    }
}
