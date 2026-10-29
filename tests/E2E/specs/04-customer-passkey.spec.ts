import { expect, test } from '@playwright/test';
import { dexLogin } from '../support/dex';
import { CUSTOMER_EMAIL } from '../support/fixtures';
import { addVirtualAuthenticator, credentialCount } from '../support/webauthn';

test.describe('Customer passkeys', () => {
    test('register a passkey after a fresh login, then log in with it', async ({ page }) => {
        const { cdp, authenticatorId } = await addVirtualAuthenticator(page);

        // A login within the last ten minutes allows registering.
        await page.goto('/account/login');
        await page.locator('a[href*="/sw6oidc/login"]').first().click();
        await dexLogin(page, CUSTOMER_EMAIL);
        await page.waitForURL(/\/account/);

        await page.goto('/account/passkey');
        await page.locator('#sw6oidc-passkey-nickname').fill('E2E key');
        await page.locator('[data-sw6oidc-passkey-register]').click();

        await expect(page.locator('.account-passkey-list table')).toContainText('E2E key', { timeout: 20_000 });
        expect(await credentialCount(cdp, authenticatorId)).toBe(1);

        await page.goto('/account/logout');
        await page.waitForURL(/\/account\/login/);

        await page.locator('[data-sw6oidc-passkey-login]').click();
        await page.waitForURL(/\/account(\/|$|\?)/, { timeout: 20_000 });
        await expect(page.locator('.account-welcome, .account-overview')).toBeVisible();
    });

    test('deleting the middle of three passkeys deletes exactly that one (R3-F3)', async ({ page }) => {
        await page.goto('/account/login');
        await page.locator('a[href*="/sw6oidc/login"]').first().click();
        await dexLogin(page, CUSTOMER_EMAIL);
        await page.waitForURL(/\/account/);
        await page.goto('/account/passkey');

        // excludeCredentials stops one authenticator from registering twice: one per key.
        for (const nickname of ['Key A', 'Key B', 'Key C']) {
            const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
            await page.locator('#sw6oidc-passkey-nickname').fill(nickname);
            await page.locator('[data-sw6oidc-passkey-register]').click();
            await expect(page.locator('.account-passkey-list table')).toContainText(nickname, { timeout: 20_000 });
            await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
        }

        const row = page.locator('.account-passkey-list tbody tr', { hasText: 'Key B' });
        await row.locator('button[type="submit"]').click();
        await row.locator('dialog button[value="confirm"]').click();
        await page.waitForURL(/\/account\/passkey/);

        const table = page.locator('.account-passkey-list table');
        await expect(table).not.toContainText('Key B');
        await expect(table).toContainText('Key A');
        await expect(table).toContainText('Key C');
    });
});
