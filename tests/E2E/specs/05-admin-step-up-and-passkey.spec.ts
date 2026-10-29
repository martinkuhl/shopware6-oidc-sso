import { expect, Page, test } from '@playwright/test';
import { dexLogin, dexSupportsAuthTime } from '../support/dex';
import { ADMIN_EMAIL, E2E_ADMIN_PASSWORD } from '../support/fixtures';
import { addVirtualAuthenticator, credentialCount } from '../support/webauthn';

async function ssoLogin(page: Page): Promise<void> {
    await page.goto('/admin');
    await page.locator('.sw6oidc-login-actions__sso-button').first().click();
    await dexLogin(page, ADMIN_EMAIL);
    await expect(page.locator('.sw-admin-menu')).toBeVisible({ timeout: 30_000 });
}

async function openPasskeyProfileTab(page: Page): Promise<void> {
    await page.goto('/admin#/sw/profile/index/sw6oidc-passkey');
    await expect(page.locator('.sw6oidc-profile-passkey')).toBeVisible({ timeout: 20_000 });
}

test.describe('Administration step-up and passkeys', () => {
    test.describe.configure({ mode: 'serial' });

    test('registering a passkey asks for re-confirmation; password confirmation works', async ({ page }) => {
        const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
        await ssoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__nickname input').fill('E2E admin key');
        await page.locator('.sw6oidc-profile-passkey__register-button').click();

        // Core's re-confirmation modal, extended with the plugin's step-up buttons.
        const modal = page.locator('.sw-verify-user-modal');
        await expect(modal).toBeVisible();
        await modal.locator('input[type="password"]').fill(E2E_ADMIN_PASSWORD);
        await modal.locator('button.mt-button--primary, button.sw-button--primary').last().click();

        await expect(page.locator('.sw6oidc-profile-passkey__grid')).toContainText('E2E admin key', { timeout: 20_000 });
        expect(await credentialCount(cdp, authenticatorId)).toBe(1);
    });

    test('step-up with a passkey (user verification)', async ({ page }) => {
        // A fresh page has a fresh authenticator: register one first, then
        // use it for the step-up of a second registration.
        const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
        await ssoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        let modal = page.locator('.sw-verify-user-modal');
        await modal.locator('input[type="password"]').fill(E2E_ADMIN_PASSWORD);
        await modal.locator('button.mt-button--primary, button.sw-button--primary').last().click();
        await expect.poll(() => credentialCount(cdp, authenticatorId)).toBe(1);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        modal = page.locator('.sw-verify-user-modal');
        await expect(modal.locator('.sw6oidc-step-up')).toBeVisible();
        await modal.locator('.sw6oidc-step-up__actions button').last().click();

        await expect.poll(() => credentialCount(cdp, authenticatorId), { timeout: 20_000 }).toBe(2);
    });

    test('step-up with SSO (fresh IdP login)', async ({ page }) => {
        test.skip(!(await dexSupportsAuthTime(page)), 'This Dex version does not send auth_time, which OIDC step-up requires.');

        await addVirtualAuthenticator(page);
        await ssoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        const modal = page.locator('.sw-verify-user-modal');

        const popupPromise = page.waitForEvent('popup');
        await modal.locator('.sw6oidc-step-up__actions button').first().click();
        const popup = await popupPromise;
        await dexLogin(popup, ADMIN_EMAIL);

        await expect(page.locator('.sw-verify-user-modal')).toHaveCount(0, { timeout: 20_000 });
    });

    test('the inactivity modal resumes only the same admin with a passkey', async ({ page }) => {
        await addVirtualAuthenticator(page);
        await ssoLogin(page);

        // A passkey this browser does not hold can't resume the session.
        await page.evaluate(() => {
            const service = (window as unknown as { Shopware: { Service: (name: string) => { forwardLogout: (a: boolean, b: boolean) => void } } }).Shopware.Service('loginService');
            service.forwardLogout(true, true);
        });

        const passkeyButton = page.locator('.sw6oidc-inactivity-login__passkey-button');
        await expect(passkeyButton).toBeVisible({ timeout: 20_000 });
        await passkeyButton.click();

        await expect(page.locator('.sw6oidc-inactivity-login__error')).toBeVisible({ timeout: 20_000 });
    });
});
