<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Integration;

use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use MartinKuhl\Sw6Oidc\Tests\Integration\Support\Sw6OidcIntegrationTestCase;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\JwtTestSigner;
use Psr\Cache\CacheItemPoolInterface;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;

/**
 * Back-Channel Logout end to end through the real kernel, routing,
 * JwtVerifier, registry and context persister — without Dex (it can't send
 * logout tokens). The IdP's JWKS is seeded into cache.app under the key
 * JwtVerifier reads, so no HTTP is needed.
 *
 * The fetched endpoints use a loopback IP: the provider write guard blocks
 * unresolvable hosts even with SW6OIDC_ALLOW_INSECURE_IDP_URLS=1, and nothing
 * is ever fetched from them. The issuer is only compared, never checked.
 */
final class BackChannelLogoutTest extends Sw6OidcIntegrationTestCase
{
    private const ISSUER = 'https://idp.integration.test';
    private const ENDPOINT_BASE = 'https://127.0.0.1';
    private const JWKS = self::ENDPOINT_BASE . '/jwks';

    private JwtTestSigner $signer;

    private string $providerId;

    protected function setUp(): void
    {
        $this->signer = new JwtTestSigner();
        $this->providerId = $this->createProvider([
            'appName' => 'bcl-' . Uuid::randomHex(),
            'clientId' => 'shop-client',
            'clientSecret' => 'secret',
            'authorizeEndpoint' => self::ENDPOINT_BASE . '/authorize',
            'accessTokenEndpoint' => self::ENDPOINT_BASE . '/token',
            'jwksEndpoint' => self::JWKS,
            'issuer' => self::ISSUER,
            'scope' => 'openid',
        ]);

        $this->seedJwks();
    }

    /**
     * N-H3: the registry is security state, so a cache:clear (or a deploy)
     * between login and logout must not make the IdP's logout a silent no-op.
     */
    public function testLogoutStillWorksAfterTheCacheWasCleared(): void
    {
        [$contextToken, $customerId] = $this->loggedInCustomerSession();
        $this->registry()->register($this->providerId, 'idp-user-1', 'idp-session-1', 'customer', $customerId, $contextToken, $this->salesChannelId());

        $cache = static::getContainer()->get('cache.app');
        \assert($cache instanceof CacheItemPoolInterface);
        $cache->clear();
        $this->seedJwks();

        $browser = $this->browser();
        $browser->request('POST', $this->shopUrl() . '/sw6oidc/backchannel-logout', ['logout_token' => $this->logoutToken(['sid' => 'idp-session-1'])]);

        self::assertSame(200, $browser->getResponse()->getStatusCode(), (string) $browser->getResponse()->getContent());
        self::assertFalse($this->contextExists($contextToken), 'the customer context was deleted');
    }

    private function seedJwks(): void
    {
        $cache = static::getContainer()->get('cache.app');
        \assert($cache instanceof CacheItemPoolInterface);
        $item = $cache->getItem('sw6oidc_jwks_' . hash('sha256', self::JWKS));
        $item->set($this->signer->jwksJson());
        $cache->save($item);
    }

    public function testLogoutTokenEndsTheRegisteredCustomerSession(): void
    {
        [$contextToken, $customerId] = $this->loggedInCustomerSession();
        $this->registry()->register($this->providerId, 'idp-user-1', 'idp-session-1', 'customer', $customerId, $contextToken, $this->salesChannelId());

        $browser = $this->browser();
        $browser->request('POST', $this->shopUrl() . '/sw6oidc/backchannel-logout', ['logout_token' => $this->logoutToken(['sid' => 'idp-session-1'])]);

        self::assertSame(200, $browser->getResponse()->getStatusCode(), (string) $browser->getResponse()->getContent());
        self::assertFalse($this->contextExists($contextToken), 'the customer context was deleted');
        self::assertSame([], $this->registry()->resolveBySid($this->providerId, 'idp-session-1'));
    }

    public function testForgedTokenIsRejectedAndEndsNothing(): void
    {
        [$contextToken, $customerId] = $this->loggedInCustomerSession();
        $this->registry()->register($this->providerId, 'idp-user-1', 'idp-session-1', 'customer', $customerId, $contextToken, $this->salesChannelId());

        $forged = (new JwtTestSigner('attacker'))->sign($this->claims(['sid' => 'idp-session-1']));

        $browser = $this->browser();
        $browser->request('POST', $this->shopUrl() . '/sw6oidc/backchannel-logout', ['logout_token' => $forged]);

        self::assertSame(400, $browser->getResponse()->getStatusCode());
        self::assertTrue($this->contextExists($contextToken));
    }

    /**
     * @return array{string, string} context token, customer id
     */
    private function loggedInCustomerSession(): array
    {
        $customerId = $this->createCustomer();
        $token = Uuid::randomHex();

        $persister = static::getContainer()->get(SalesChannelContextPersister::class);
        \assert($persister instanceof SalesChannelContextPersister);
        $persister->save($token, ['customerId' => $customerId], $this->salesChannelId(), $customerId);

        return [$token, $customerId];
    }

    private function createCustomer(): string
    {
        $connection = static::getContainer()->get('Doctrine\DBAL\Connection');
        $id = Uuid::randomHex();
        $addressId = Uuid::randomHex();
        $salutationId = (string) $connection->fetchOne('SELECT LOWER(HEX(id)) FROM salutation LIMIT 1');
        $countryId = (string) $connection->fetchOne('SELECT LOWER(HEX(id)) FROM country LIMIT 1');
        $groupId = (string) $connection->fetchOne('SELECT LOWER(HEX(id)) FROM customer_group LIMIT 1');

        static::getContainer()->get('customer.repository')->create([[
            'id' => $id,
            'salesChannelId' => $this->salesChannelId(),
            'groupId' => $groupId,
            'defaultBillingAddressId' => $addressId,
            'defaultShippingAddressId' => $addressId,
            'addresses' => [['id' => $addressId, 'firstName' => 'Bcl', 'lastName' => 'Test', 'street' => 'Street 1', 'zipcode' => '12345', 'city' => 'City', 'countryId' => $countryId, 'salutationId' => $salutationId]],
            'customerNumber' => 'BCL-' . substr($id, 0, 8),
            'firstName' => 'Bcl',
            'lastName' => 'Test',
            'email' => 'bcl-' . substr($id, 0, 8) . '@example.com',
            'password' => 'not-used-' . $id,
            'salutationId' => $salutationId,
        ]], \Shopware\Core\Framework\Context::createDefaultContext());

        return $id;
    }

    private function contextExists(string $token): bool
    {
        return static::getContainer()->get('Doctrine\DBAL\Connection')->fetchOne('SELECT 1 FROM sales_channel_api_context WHERE token = :token', ['token' => $token]) !== false;
    }

    private function registry(): Sw6OidcSessionRegistry
    {
        $registry = static::getContainer()->get(Sw6OidcSessionRegistry::class);
        \assert($registry instanceof Sw6OidcSessionRegistry);

        return $registry;
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function logoutToken(array $overrides): string
    {
        return $this->signer->sign($this->claims($overrides));
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'aud' => 'shop-client',
            'iat' => time(),
            'exp' => time() + 120,
            'jti' => Uuid::randomHex(),
            'sub' => 'idp-user-1',
            'events' => [JwtVerifier::BACKCHANNEL_LOGOUT_EVENT => new \stdClass()],
        ], $overrides);
    }
}
