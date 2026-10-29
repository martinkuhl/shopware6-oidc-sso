/** Fixed ids and credentials shared by the setup and the specs (test-only values). */
export const SHOP_URL = process.env.SW6OIDC_E2E_SHOP_URL ?? 'http://localhost';
export const DEX_URL = 'http://dex:5556/dex';

export const SHOP_ADMIN = { username: 'admin', password: 'shopware' };
export const DEX_PASSWORD = 'password';
export const CUSTOMER_EMAIL = 'customer@example.com';
export const ADMIN_EMAIL = 'admin@example.com';

export const CUSTOMER_PROVIDER_ID = '0190e2e0000070008000000000000c01';
export const ADMIN_PROVIDER_ID = '0190e2e0000070008000000000000a01';
export const E2E_ROLE_ID = '0190e2e0000070008000000000000e01';
export const E2E_ADMIN_USER_ID = '0190e2e0000070008000000000000f01';

export const CLIENT_ID = 'shopware-e2e';
export const CLIENT_SECRET = 'shopware-e2e-secret';

/** Known password of the linked Administration user: core's password re-confirmation bootstraps the first admin passkey. */
export const E2E_ADMIN_USERNAME = 'e2e-admin';
export const E2E_ADMIN_PASSWORD = 'E2e-admin-password-1!';
