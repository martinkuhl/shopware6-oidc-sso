<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Integration\Support;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Test\TestCaseBase\KernelLifecycleManager;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Test\TestDefaults;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;

/**
 * Base for the integration suite: a real kernel with the plugin active, every
 * test wrapped in a rolled-back DB transaction (IntegrationTestBehaviour),
 * and helpers to create providers and talk to Dex.
 */
abstract class Sw6OidcIntegrationTestCase extends TestCase
{
    use IntegrationTestBehaviour;

    protected const DEX_CLIENT_ID = 'shopware';
    protected const DEX_CLIENT_SECRET = 'shopware-integration-secret';
    protected const PASSWORD = 'password';

    protected function browser(): KernelBrowser
    {
        $browser = KernelLifecycleManager::createBrowser(static::getKernel());
        $browser->followRedirects(false);

        return $browser;
    }

    protected function shopUrl(): string
    {
        return rtrim((string) ($_SERVER['APP_URL'] ?? $_ENV['APP_URL'] ?? 'http://localhost:8000'), '/');
    }

    protected function dexIssuer(): string
    {
        return rtrim((string) ($_SERVER['SW6OIDC_IT_DEX_ISSUER'] ?? $_ENV['SW6OIDC_IT_DEX_ISSUER'] ?? 'http://127.0.0.1:5556/dex'), '/');
    }

    /**
     * Skips the test when Dex isn't running, so the kernel-only tests of the
     * suite still run without Docker.
     */
    protected function requireDex(): void
    {
        $context = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);

        if (@file_get_contents($this->dexIssuer() . '/.well-known/openid-configuration', false, $context) === false) {
            self::markTestSkipped('Dex is not running at ' . $this->dexIssuer() . ' (see tests/Integration/README.md).');
        }
    }

    /**
     * A provider pointing at the running Dex.
     *
     * @param array<string, mixed> $overrides
     */
    protected function createDexProvider(array $overrides = []): string
    {
        $issuer = $this->dexIssuer();

        return $this->createProvider(array_merge([
            'appName' => 'dex-' . Uuid::randomHex(),
            'displayName' => 'Dex',
            'clientId' => self::DEX_CLIENT_ID,
            'clientSecret' => self::DEX_CLIENT_SECRET,
            'authorizeEndpoint' => $issuer . '/auth',
            'accessTokenEndpoint' => $issuer . '/token',
            'userInfoEndpoint' => $issuer . '/userinfo',
            'jwksEndpoint' => $issuer . '/keys',
            'issuer' => $issuer,
            'scope' => 'openid profile email',
        ], $overrides));
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function createProvider(array $data): string
    {
        $id = Uuid::randomHex();

        static::getContainer()->get('sw6oidc_provider.repository')->create([array_merge([
            'id' => $id,
            'pkceFlow' => 'S256',
            'groupAttribute' => 'groups',
            'loginType' => 'both',
            'isActive' => true,
            'autoCreateCustomer' => true,
            'httpTimeout' => 10,
            'jwksCacheTtl' => 300,
        ], $data)], Context::createDefaultContext());

        return $id;
    }

    /**
     * The Storefront sales channel serving APP_URL (the one storefront
     * routes resolve), falling back to the Store API test channel.
     */
    protected function salesChannelId(): string
    {
        $id = static::getContainer()->get('Doctrine\DBAL\Connection')->fetchOne(
            'SELECT LOWER(HEX(sales_channel_id)) FROM sales_channel_domain WHERE url = :url',
            ['url' => $this->shopUrl()],
        );

        return \is_string($id) ? $id : TestDefaults::SALES_CHANNEL;
    }

    protected function customerIdByEmail(string $email): ?string
    {
        $id = static::getContainer()->get('Doctrine\DBAL\Connection')->fetchOne(
            'SELECT LOWER(HEX(id)) FROM customer WHERE email = :email AND guest = 0',
            ['email' => $email],
        );

        return \is_string($id) ? $id : null;
    }
}
