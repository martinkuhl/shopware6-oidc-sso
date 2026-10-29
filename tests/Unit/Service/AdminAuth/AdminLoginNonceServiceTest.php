<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use Symfony\Component\HttpFoundation\RequestStack;
use MartinKuhl\Sw6Oidc\Service\Security\BrowserBinding;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginNonce;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminLoginNonceService;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdminLoginNonceService::class)]
#[CoversClass(AdminLoginNonce::class)]
final class AdminLoginNonceServiceTest extends TestCase
{
    public function testNonceCarriesReferencesOnlyAndIsSingleUse(): void
    {
        $cache = new InMemoryAtomicCache();
        $service = new AdminLoginNonceService($cache, new BrowserBinding(new RequestStack()));
        $nonce = $service->createNonce('user-1', 'provider-1', 'registry-1');

        self::assertStringNotContainsString('token', implode('', $cache->items), 'no id_token copies (N-L10)');
        self::assertEquals(new AdminLoginNonce('user-1', 'provider-1', 'registry-1'), $service->redeemNonce($nonce));
        self::assertNull($service->redeemNonce($nonce));
    }

    public function testUserIdOnlyNonce(): void
    {
        $service = new AdminLoginNonceService(new InMemoryAtomicCache(), new BrowserBinding(new RequestStack()));

        self::assertEquals(new AdminLoginNonce('user-1'), $service->redeemNonce($service->createNonce('user-1')));
    }

    public function testMalformedEntryIsRejected(): void
    {
        $cache = new InMemoryAtomicCache();
        $cache->items['sw6oidc_admin_nonce_legacy'] = '0190a1b2c3d4e5f60718293a4b5c6d7e';

        self::assertNull((new AdminLoginNonceService($cache, new BrowserBinding(new RequestStack())))->redeemNonce('legacy'));
    }

    public function testUnknownOrEmptyNonce(): void
    {
        $service = new AdminLoginNonceService(new InMemoryAtomicCache(), new BrowserBinding(new RequestStack()));

        self::assertNull($service->redeemNonce(null));
        self::assertNull($service->redeemNonce(''));
        self::assertNull($service->redeemNonce('nope'));
    }
}
