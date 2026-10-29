<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Integration;

use MartinKuhl\Sw6Oidc\Tests\Integration\Support\DexLoginDriver;
use MartinKuhl\Sw6Oidc\Tests\Integration\Support\Sw6OidcIntegrationTestCase;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Claims-based access control against the claims a real IdP (Dex) sends:
 * `email`, `email_verified` (true), `name`.
 */
final class AccessControlRulesTest extends Sw6OidcIntegrationTestCase
{
    private const EMAIL = 'customer@example.com';

    protected function setUp(): void
    {
        $this->requireDex();
    }

    public function testMatchingRulesLetTheCustomerIn(): void
    {
        $this->loginWithRules([
            // Domain restriction: email_domain, never a substring match (N-M11).
            ['claimKey' => 'email', 'operator' => 'email_domain', 'value' => 'EXAMPLE.com'],
            ['claimKey' => 'email_verified', 'operator' => 'eq', 'value' => 'true'],
        ]);

        self::assertNotNull($this->customerIdByEmail(self::EMAIL));
    }

    public function testFailingRuleDeniesBeforeAnyAccountIsCreated(): void
    {
        $location = $this->loginWithRules([
            ['claimKey' => 'email_verified', 'operator' => 'eq', 'value' => 'false', 'errorMessage' => 'Verified accounts only.'],
        ]);

        self::assertStringContainsString('/account/login', $location);
        self::assertNull($this->customerIdByEmail(self::EMAIL), 'nothing was provisioned');
    }

    /**
     * @param list<array<string, string>> $rules
     *
     * @return string the callback's redirect target
     */
    private function loginWithRules(array $rules): string
    {
        $providerId = $this->createDexProvider([
            'loginType' => 'customer',
            'accessControlRules' => array_map(
                static fn (array $rule, int $index): array => array_merge(['id' => Uuid::randomHex(), 'sortOrder' => $index], $rule),
                $rules,
                array_keys($rules),
            ),
        ]);
        $browser = $this->browser();

        $browser->request('GET', $this->shopUrl() . '/sw6oidc/login?providerId=' . $providerId);
        $callbackUrl = (new DexLoginDriver())->login((string) $browser->getResponse()->headers->get('Location'), self::EMAIL, self::PASSWORD, $this->shopUrl());
        $browser->request('GET', $callbackUrl);

        return (string) $browser->getResponse()->headers->get('Location');
    }
}
