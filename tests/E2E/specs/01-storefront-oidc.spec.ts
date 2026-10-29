import { expect, test } from '@playwright/test';
import { dexLogin } from '../support/dex';
import { CUSTOMER_EMAIL } from '../support/fixtures';

test.describe('Storefront OIDC login', () => {
    test('a customer logs in with SSO and out again', async ({ page }) => {
        await page.goto('/account/login');

        await page.locator('a[href*="/sw6oidc/login"]').first().click();
        await dexLogin(page, CUSTOMER_EMAIL);

        // JIT-created (or bound) and logged in: the account area.
        await page.waitForURL(/\/account(\/|$|\?)/);
        await expect(page.locator('.account-welcome, .account-overview')).toBeVisible();

        await page.goto('/account/logout');
        await page.waitForURL(/\/account\/login/);
        await expect(page.locator('a[href*="/sw6oidc/login"]').first()).toBeVisible();
    });

    test('a checkout redirect survives the SSO round trip', async ({ page }) => {
        await page.goto('/account/login?redirectTo=frontend.account.profile.page');

        await page.locator('a[href*="/sw6oidc/login"]').first().click();
        await dexLogin(page, CUSTOMER_EMAIL);

        await page.waitForURL(/\/account\/profile/);
    });
});
