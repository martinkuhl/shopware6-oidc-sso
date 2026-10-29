import { expect, test } from '@playwright/test';
import { adminSsoLogin } from '../support/admin-login';

test.describe('Administration OIDC login', () => {
    test('an admin logs in with SSO and the dashboard survives a reload', async ({ page }) => {
        // Nonce hand-off back into the SPA, then the full app boot.
        await adminSsoLogin(page);
        expect(page.url()).not.toContain('sw6oidc_nonce');

        // Regression: a login that skipped core's reload left a blank dashboard.
        await page.reload();
        await expect(page.locator('.sw-admin-menu')).toBeVisible({ timeout: 30_000 });
    });

    test('a forged or reused nonce is rejected', async ({ page }) => {
        await page.goto('/admin#/login?sw6oidc_nonce=not-a-real-nonce');

        await expect(page.locator('.sw6oidc-login-actions__error')).toBeVisible();
        await expect(page.locator('.sw-admin-menu')).toHaveCount(0);
    });
});
