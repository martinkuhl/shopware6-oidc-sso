import { expect, Page } from '@playwright/test';
import { dexLogin } from './dex';
import { ADMIN_EMAIL } from './fixtures';

/**
 * Administration SSO login through Dex, up to the booted app. A refused
 * hand-off (link required, nonce exchange failed, …) ends on the login page
 * with the plugin's error: report that instead of a bare menu timeout.
 */
export async function adminSsoLogin(page: Page, email: string = ADMIN_EMAIL): Promise<void> {
    await page.goto('/admin');
    await page.locator('.sw6oidc-login-actions__sso-button').first().click();
    await dexLogin(page, email);

    const menu = page.locator('.sw-admin-menu');
    const error = page.locator('.sw6oidc-login-actions__error');
    await expect(menu.or(error).first()).toBeVisible({ timeout: 30_000 });

    if (await error.isVisible()) {
        throw new Error(`Administration SSO login refused at ${page.url()}: ${(await error.innerText()).trim()}`);
    }
}
