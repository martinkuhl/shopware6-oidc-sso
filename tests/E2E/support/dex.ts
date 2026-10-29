import { expect, Page } from '@playwright/test';
import { DEX_PASSWORD } from './fixtures';

/**
 * Completes Dex's password login form (the page the shop redirected to).
 */
export async function dexLogin(page: Page, email: string): Promise<void> {
    await page.waitForURL(/dex:5556\/dex\/auth/);
    await page.locator('#login').fill(email);
    await page.locator('#password').fill(DEX_PASSWORD);
    await page.locator('#submit-login').click();
}

/**
 * Whether Dex puts auth_time into id_tokens (needed for OIDC step-up).
 */
export async function dexSupportsAuthTime(page: Page): Promise<boolean> {
    const response = await page.request.get('http://dex:5556/dex/.well-known/openid-configuration');
    expect(response.ok()).toBeTruthy();
    const discovery = await response.json();

    return Array.isArray(discovery.claims_supported) && discovery.claims_supported.includes('auth_time');
}
