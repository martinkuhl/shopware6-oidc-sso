import { expect, test } from '@playwright/test';
import { adminApi, upsert } from '../support/admin-api';
import { CUSTOMER_PROVIDER_ID } from '../support/fixtures';

/**
 * SSO-only mode: the customer provider disables password login. Needs the
 * binding the storefront OIDC spec created (lockout guard).
 */
test.describe('SSO-only customer login', () => {
    test.beforeAll(async () => {
        const api = await adminApi();
        await upsert(api, 'sw6oidc_provider', [{ id: CUSTOMER_PROVIDER_ID, disableNonOidcCustomerLogin: true }]);
        await api.dispose();
    });

    test.afterAll(async () => {
        const api = await adminApi();
        await upsert(api, 'sw6oidc_provider', [{ id: CUSTOMER_PROVIDER_ID, disableNonOidcCustomerLogin: false }]);
        await api.dispose();
    });

    test('the password form is hidden and the SSO button shown', async ({ page }) => {
        await page.goto('/account/login');

        await expect(page.locator('a[href*="/sw6oidc/login"]').first()).toBeVisible();
        await expect(page.locator('#loginMail')).toHaveCount(0);
    });

    test('the Store API refuses password logins and registrations', async ({ request }) => {
        const api = await adminApi();
        const channels = await (await api.post('/api/search/sales-channel', {
            data: { filter: [{ type: 'equals', field: 'typeId', value: '8a243080f92e4c719546314b577cf82b' }], limit: 1 },
        })).json();
        await api.dispose();

        const accessKey = channels.data[0].accessKey as string;

        const login = await request.post('/store-api/account/login', {
            headers: { 'sw-access-key': accessKey },
            data: { username: 'customer@example.com', password: 'whatever' },
        });
        expect(login.status()).toBe(403);

        const register = await request.post('/store-api/account/register', {
            headers: { 'sw-access-key': accessKey },
            data: {
                email: `new-${Date.now()}@example.com`,
                password: 'Some-password-1',
                firstName: 'New',
                lastName: 'Customer',
                storefrontUrl: 'http://localhost',
                billingAddress: { street: 'Street 1', zipcode: '12345', city: 'City', countryId: channels.data[0].countryId },
            },
        });
        expect(register.status()).toBe(403);
    });
});
