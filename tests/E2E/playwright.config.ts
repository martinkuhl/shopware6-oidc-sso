import { defineConfig, devices } from '@playwright/test';

/**
 * One worker, specs in file order: they share one shop and build on each
 * other (the SSO login creates the binding the SSO-only spec needs, the
 * passkey spec registers what it later logs in with).
 */
export default defineConfig({
    testDir: './specs',
    fullyParallel: false,
    workers: 1,
    retries: process.env.CI ? 1 : 0,
    timeout: 90_000,
    reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
    globalSetup: './setup/global-setup.ts',
    use: {
        baseURL: process.env.SW6OIDC_E2E_SHOP_URL ?? 'http://localhost',
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        locale: 'en-GB',
    },
    projects: [
        {
            // Chromium: the virtual WebAuthn authenticator is a CDP feature.
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],
});
