import { expect, Page, test } from '@playwright/test';
import { ADMIN_PROVIDER_ID, E2E_ADMIN_PASSWORD, E2E_ADMIN_USERNAME, E2E_ROLE_ID, SHOP_ADMIN } from '../support/fixtures';

/**
 * Opens every Administration page the plugin adds or extends and fails on
 * any console error or uncaught exception (R4-L7): a template error (R3-F1)
 * or a broken component only shows up in a real browser. Runs first, while
 * password login is still on (spec 03 turns it off).
 */
const PLUGIN_PAGES = [
    '#/sw6oidc/provider/index',
    `#/sw6oidc/provider/detail/${ADMIN_PROVIDER_ID}`,
    '#/sw6oidc/provider/create',
    '#/sw6oidc/passkey/index',
    '#/sw6oidc/sessions/index',
    '#/sw/profile/index/general',
    '#/sw/profile/index/sw6oidc-passkey',
];

function collectErrors(page: Page): string[] {
    const errors: string[] = [];

    page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
    page.on('console', (message) => {
        if (message.type() === 'error') {
            errors.push(`console: ${message.text()}`);
        }
    });

    return errors;
}

async function passwordLogin(page: Page, username: string, password: string): Promise<void> {
    await page.goto('/admin#/login');
    await page.locator('input[name="sw-field--username"]').fill(username);
    await page.locator('input[name="sw-field--password"]').fill(password);
    await page.locator('.sw-login__login-action').click();
    await expect(page.locator('.sw-admin-menu')).toBeVisible({ timeout: 30_000 });
}

async function visitAll(page: Page, pages: string[]): Promise<void> {
    for (const hash of pages) {
        await page.goto(`/admin${hash}`);
        await expect(page.locator('.sw-page, .sw-profile-index').first()).toBeVisible({ timeout: 30_000 });
        // Let lazy components and their requests settle.
        await page.waitForLoadState('networkidle');
    }
}

test.describe('Administration smoke test', () => {
    test('every plugin page renders for a superadmin without console errors', async ({ page }) => {
        const errors = collectErrors(page);

        await passwordLogin(page, SHOP_ADMIN.username, SHOP_ADMIN.password);
        await visitAll(page, PLUGIN_PAGES);

        expect(errors).toEqual([]);
    });

    test('the provider pages render read-only for a viewer role', async ({ page }) => {
        const errors = collectErrors(page);

        await passwordLogin(page, E2E_ADMIN_USERNAME, E2E_ADMIN_PASSWORD);
        await visitAll(page, ['#/sw6oidc/provider/index', `#/sw6oidc/provider/detail/${ADMIN_PROVIDER_ID}`]);

        // A viewer can't save (R3-F14).
        await expect(page.locator('.sw6oidc-provider-detail__save-action')).toBeDisabled();
        expect(errors).toEqual([]);
    });

    test('the role editor offers the plugin privileges', async ({ page }) => {
        await passwordLogin(page, SHOP_ADMIN.username, SHOP_ADMIN.password);
        await page.goto(`/admin#/sw/users/permissions/role/detail/${E2E_ROLE_ID}`);

        // Registered once the privileges service is ready (R3-F2, R6-L2).
        await expect(page.locator('[class*="entry_sw6oidc_provider"]').first()).toBeVisible({ timeout: 30_000 });
    });
});
