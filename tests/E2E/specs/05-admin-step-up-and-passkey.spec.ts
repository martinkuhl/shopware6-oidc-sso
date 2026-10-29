import { expect, Locator, Page, test } from '@playwright/test';
import { adminSsoLogin } from '../support/admin-login';
import { dexLogin, dexSupportsAuthTime } from '../support/dex';
import { ADMIN_EMAIL, E2E_ADMIN_PASSWORD } from '../support/fixtures';
import { addVirtualAuthenticator, credentialCount } from '../support/webauthn';

async function openPasskeyProfileTab(page: Page): Promise<void> {
    await page.goto('/admin#/sw/profile/index/sw6oidc-passkey');
    await expect(page.locator('.sw6oidc-profile-passkey')).toBeVisible({ timeout: 20_000 });
}

/**
 * Core's re-confirmation modal (sw-verify-user-modal), extended with the
 * plugin's step-up buttons. Its root is a bare sw-modal without a class of
 * its own: found by core's password field in it.
 */
function verifyUserModal(page: Page): Locator {
    return page.locator('.sw-modal').filter({ has: page.locator('.sw-settings-user-detail__confirm-password') });
}

test.describe('Administration step-up and passkeys', () => {
    test.describe.configure({ mode: 'serial' });

    test('registering a passkey asks for re-confirmation; password confirmation works', async ({ page }) => {
        const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
        await adminSsoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__nickname input').fill('E2E admin key');
        await page.locator('.sw6oidc-profile-passkey__register-button').click();

        const modal = verifyUserModal(page);
        await expect(modal).toBeVisible();
        await modal.locator('input[type="password"]').fill(E2E_ADMIN_PASSWORD);
        await modal.locator('button.mt-button--primary, button.sw-button--primary').last().click();

        // The authenticator first: on a retry the grid already lists the key
        // the failed attempt stored on the server.
        await expect.poll(() => credentialCount(cdp, authenticatorId), { timeout: 20_000 }).toBe(1);
        await expect(page.locator('.sw6oidc-profile-passkey__grid')).toContainText('E2E admin key');
    });

    test('step-up with a passkey (user verification)', async ({ page }) => {
        // A fresh page has a fresh authenticator: register one first, then
        // use it to confirm the next registration.
        const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
        await adminSsoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        let modal = verifyUserModal(page);
        await modal.locator('input[type="password"]').fill(E2E_ADMIN_PASSWORD);
        await modal.locator('button.mt-button--primary, button.sw-button--primary').last().click();
        await expect.poll(() => credentialCount(cdp, authenticatorId)).toBe(1);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        modal = verifyUserModal(page);
        await expect(modal.locator('.sw6oidc-step-up')).toBeVisible();
        const verifyResponse = page.waitForResponse((response) => response.url().includes('/api/sw6oidc/admin/step-up/passkey/verify'));
        await modal.locator('.sw6oidc-step-up__actions button').last().click();

        expect((await verifyResponse).ok()).toBe(true);
        await expect(verifyUserModal(page)).toHaveCount(0);
        // The registration it confirmed is refused by this authenticator:
        // its key is in excludeCredentials, so no second key on one device.
        expect(await credentialCount(cdp, authenticatorId)).toBe(1);
    });

    test('step-up with SSO (fresh IdP login)', async ({ page }) => {
        test.skip(!(await dexSupportsAuthTime(page)), 'This Dex version does not send auth_time, which OIDC step-up requires.');

        await addVirtualAuthenticator(page);
        await adminSsoLogin(page);
        await openPasskeyProfileTab(page);

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        const modal = verifyUserModal(page);

        const popupPromise = page.waitForEvent('popup');
        await modal.locator('.sw6oidc-step-up__actions button').first().click();
        const popup = await popupPromise;
        await dexLogin(popup, ADMIN_EMAIL);

        await expect(verifyUserModal(page)).toHaveCount(0, { timeout: 20_000 });
    });

    test('step-up with SSO is refused when the IdP sends no auth_time', async ({ page }) => {
        test.skip(await dexSupportsAuthTime(page), 'This Dex version sends auth_time: the step-up test above covers it.');

        await addVirtualAuthenticator(page);
        await adminSsoLogin(page);
        await openPasskeyProfileTab(page);

        // Only a redeemed step-up nonce asks for a token.
        const tokenRequests: string[] = [];
        page.on('request', (request) => {
            if (request.url().includes('/api/sw6oidc/admin/step-up/token')) {
                tokenRequests.push(request.url());
            }
        });

        await page.locator('.sw6oidc-profile-passkey__register-button').click();
        const modal = verifyUserModal(page);

        const popupPromise = page.waitForEvent('popup');
        await modal.locator('.sw6oidc-step-up__actions button').first().click();
        const popup = await popupPromise;
        const popupClosed = popup.waitForEvent('close', { timeout: 20_000 });
        await dexLogin(popup, ADMIN_EMAIL);
        // The callback reports the refusal to the opener and closes.
        await popupClosed;

        // Not confirmed: the modal stays open, ready for another method.
        await expect(modal).toBeVisible();
        await expect(modal.locator('.sw6oidc-step-up__actions button').first()).toBeEnabled();
        expect(tokenRequests).toEqual([]);
    });

    test('the inactivity modal resumes only the same admin with a passkey', async ({ page }) => {
        await addVirtualAuthenticator(page);
        await adminSsoLogin(page);

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
