import { expect, test } from '@playwright/test';
import { dexLogin } from '../support/dex';
import { ADMIN_EMAIL } from '../support/fixtures';

test.describe('Administration OIDC login', () => {
    test('an admin logs in with SSO and the dashboard survives a reload', async ({ page }) => {
        await page.goto('/admin');

        await page.locator('.sw6oidc-login-actions__sso-button').first().click();
        await dexLogin(page, ADMIN_EMAIL);

        // Nonce hand-off back into the SPA, then the full app boot.
        await expect(page.locator('.sw-admin-menu')).toBeVisible({ timeout: 30_000 });
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
