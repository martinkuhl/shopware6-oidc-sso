<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSsoSchema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SsoOnlyInvariant::class)]
final class SsoOnlyInvariantTest extends TestCase
{
    private SqliteSsoSchema $db;

    private SsoOnlyInvariant $invariant;

    protected function setUp(): void
    {
        $this->db = new SqliteSsoSchema();
        $this->invariant = new SsoOnlyInvariant($this->db->connection);
    }

    public function testPolicyIsOnlyOnForActiveProvidersServingThatLoginType(): void
    {
        $this->db->provider(['disable_non_oidc_admin_login' => 1, 'is_active' => 0]);
        $this->db->provider(['disable_non_oidc_admin_login' => 1, 'login_type' => 'customer']);

        self::assertFalse($this->invariant->passwordLoginDisabled('admin'));

        $this->db->provider(['disable_non_oidc_admin_login' => 1, 'login_type' => 'admin']);

        self::assertTrue($this->invariant->passwordLoginDisabled('admin'));
        self::assertFalse($this->invariant->passwordLoginDisabled('customer'));
    }

    public function testBreakGlassTurnsThePolicyOff(): void
    {
        $this->db->provider(['disable_non_oidc_admin_login' => 1]);

        $invariant = new SsoOnlyInvariant($this->db->connection, true);

        self::assertFalse($invariant->passwordLoginDisabled('admin'));
        self::assertTrue($invariant->holds());
    }

    /**
     * R3-H7 scenario 1: a provider with the flag is re-activated by a
     * payload of `is_active` only, after its only bound admin was deactivated.
     */
    public function testReactivationWithOnlyAnInactiveBoundAdminBreaksTheInvariant(): void
    {
        $provider = $this->db->provider(['disable_non_oidc_admin_login' => 1, 'is_active' => 0]);
        $this->db->bind($provider, $this->db->admin(active: false));

        self::assertTrue($this->invariant->holds());
        self::assertFalse($this->invariant->holds([$provider => ['is_active' => 1]]));
    }

    /**
     * R3-H7 scenario 2: a customer-only provider with the flag is re-scoped to both.
     */
    public function testRescopingToAdminsIsSeen(): void
    {
        $provider = $this->db->provider(['disable_non_oidc_admin_login' => 1, 'login_type' => 'customer']);

        self::assertFalse($this->invariant->passwordLoginDisabled('admin'));
        self::assertTrue($this->invariant->passwordLoginDisabled('admin', [$provider => ['login_type' => 'both']]));
        self::assertFalse($this->invariant->holds([$provider => ['login_type' => 'both']]));
    }

    /**
     * R3-H7 scenario 3: unlinking or deactivating the last bound admin.
     */
    public function testRemovingTheLastBoundAdminBreaksTheInvariant(): void
    {
        $provider = $this->db->provider(['disable_non_oidc_admin_login' => 1]);
        $admin = $this->db->admin();
        $this->db->bind($provider, $admin);

        self::assertTrue($this->invariant->holds());
        self::assertFalse($this->invariant->holds(unboundUserIds: [$admin]));
        self::assertFalse($this->invariant->holds(removedUserIds: [$admin]));

        $this->db->bind($provider, $this->db->admin());

        self::assertTrue($this->invariant->holds(unboundUserIds: [$admin]));
    }

    public function testDeletingTheProviderIsSeen(): void
    {
        $flagged = $this->db->provider(['disable_non_oidc_admin_login' => 1]);
        $other = $this->db->provider();
        $this->db->bind($other, $this->db->admin());

        self::assertTrue($this->invariant->holds());
        self::assertFalse($this->invariant->passwordLoginDisabled('admin', [$flagged => null]));
        self::assertFalse($this->invariant->adminAccessPossible([$other => null]));
        self::assertFalse($this->invariant->holds([$other => null]));
    }

    public function testUnboundActiveAdminsIgnoreInactiveAccountsAndInactiveProviders(): void
    {
        $active = $this->db->provider();
        $inactive = $this->db->provider(['is_active' => 0]);
        $bound = $this->db->admin();
        $boundToInactive = $this->db->admin();
        $this->db->admin(active: false);
        $this->db->bind($active, $bound);
        $this->db->bind($inactive, $boundToInactive);

        self::assertSame([$boundToInactive], $this->invariant->unboundActiveAdminIds());
        self::assertSame([], $this->invariant->unboundActiveAdminIds([$inactive => ['is_active' => 1]]));
    }

    /**
     * R3-M9: bindings left on a previous issuer can't log in, so they don't
     * keep SSO-only mode "safe" — also on later writes.
     */
    public function testOnlyBindingsOfTheCurrentIssuerCount(): void
    {
        $provider = $this->db->provider(['disable_non_oidc_admin_login' => 1, 'issuer' => 'https://new-tenant.example']);
        $this->db->bind($provider, $this->db->admin(), issuer: 'https://old-tenant.example');

        self::assertFalse($this->invariant->adminAccessPossible());
        self::assertTrue($this->invariant->adminAccessPossible(rebindProviderIds: [$provider]));

        $this->db->bind($provider, $this->db->admin(), issuer: 'https://new-tenant.example');

        self::assertTrue($this->invariant->adminAccessPossible());
    }

    /**
     * R6-L1: the unbound list (lockout confirmation, password-session
     * revocation) agrees with the invariant about bindings on an old issuer.
     */
    public function testBindingsOnAPreviousIssuerAreUnbound(): void
    {
        $provider = $this->db->provider(['issuer' => 'https://new-tenant.example']);
        $stale = $this->db->admin();
        $current = $this->db->admin();
        $this->db->bind($provider, $stale, issuer: 'https://old-tenant.example');
        $this->db->bind($provider, $current, issuer: 'https://new-tenant.example');

        self::assertSame([$stale], $this->invariant->unboundActiveAdminIds());
        self::assertSame([], $this->invariant->unboundActiveAdminIds(rebindProviderIds: [$provider]));
    }

    public function testLoginButtonVisibility(): void
    {
        $provider = $this->db->provider(['show_admin_link' => 0]);

        self::assertFalse($this->invariant->loginButtonVisible('admin'));
        self::assertTrue($this->invariant->loginButtonVisible('admin', [$provider => ['show_admin_link' => 1]]));
        self::assertTrue($this->invariant->loginButtonVisible('customer'));
    }
}
