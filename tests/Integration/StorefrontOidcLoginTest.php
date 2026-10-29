<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Integration;

use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSessionRegistry;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Integration\Support\DexLoginDriver;
use MartinKuhl\Sw6Oidc\Tests\Integration\Support\Sw6OidcIntegrationTestCase;

/**
 * Full Storefront OIDC login against a real Dex: authorize redirect → Dex
 * login form → callback → token exchange + id_token verification over real
 * HTTP → JIT customer creation → session registry + activity log.
 */
final class StorefrontOidcLoginTest extends Sw6OidcIntegrationTestCase
{
    private const EMAIL = 'customer@example.com';

    protected function setUp(): void
    {
        $this->requireDex();
    }

    public function testCustomerIsCreatedAndLoggedIn(): void
    {
        $providerId = $this->createDexProvider(['loginType' => 'customer']);
        $browser = $this->browser();

        $browser->request('GET', $this->shopUrl() . '/sw6oidc/login?providerId=' . $providerId);
        $authorizeUrl = (string) $browser->getResponse()->headers->get('Location');
        self::assertStringStartsWith($this->dexIssuer() . '/auth', $authorizeUrl);

        $callbackUrl = (new DexLoginDriver())->login($authorizeUrl, self::EMAIL, self::PASSWORD, $this->shopUrl());

        $browser->request('GET', $callbackUrl);
        $response = $browser->getResponse();

        self::assertSame(302, $response->getStatusCode());
        self::assertStringNotContainsString('/account/login', (string) $response->headers->get('Location'), 'not bounced back to the login page');

        $customerId = $this->customerIdByEmail(self::EMAIL);
        self::assertNotNull($customerId, 'the customer was JIT-created');

        $registry = static::getContainer()->get(Sw6OidcSessionRegistry::class);
        \assert($registry instanceof Sw6OidcSessionRegistry);
        self::assertNotSame([], SqliteSessionRegistry::sessionsOf($registry, 'customer', $customerId), 'the session was registered');

        $activity = static::getContainer()->get('Doctrine\DBAL\Connection')->fetchAssociative(
            'SELECT login_method, logged_out_at FROM sw6oidc_session_activity WHERE user_id = UNHEX(:id)',
            ['id' => $customerId],
        );
        self::assertSame(['login_method' => 'oidc', 'logged_out_at' => null], $activity);
    }

    public function testReplayedCallbackIsRejected(): void
    {
        $providerId = $this->createDexProvider(['loginType' => 'customer']);
        $browser = $this->browser();

        $browser->request('GET', $this->shopUrl() . '/sw6oidc/login?providerId=' . $providerId);
        $callbackUrl = (new DexLoginDriver())->login((string) $browser->getResponse()->headers->get('Location'), self::EMAIL, self::PASSWORD, $this->shopUrl());

        $browser->request('GET', $callbackUrl);
        $browser->request('GET', $callbackUrl);

        self::assertStringContainsString('/account/login', (string) $browser->getResponse()->headers->get('Location'), 'state is single-use');
    }
}
