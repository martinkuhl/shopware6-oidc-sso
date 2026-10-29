import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { adminApi, saveUserEntity, upsert } from '../support/admin-api';
import {
    ADMIN_EMAIL,
    ADMIN_PROVIDER_ID,
    CLIENT_ID,
    CLIENT_SECRET,
    CUSTOMER_PROVIDER_ID,
    DEX_URL,
    E2E_ADMIN_PASSWORD,
    E2E_ADMIN_USER_ID,
    E2E_ROLE_ID,
    SHOP_URL,
} from '../support/fixtures';

const E2E_DIR = path.resolve(__dirname, '..');

function shop(command: string): string {
    return execFileSync('docker', ['compose', 'exec', '-T', 'shop', 'bash', '-lc', command], {
        cwd: E2E_DIR,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'inherit'],
    });
}

async function waitForShop(): Promise<void> {
    const deadline = Date.now() + 300_000;

    while (Date.now() < deadline) {
        try {
            const response = await fetch(`${SHOP_URL}/api/_info/health-check`);

            if (response.ok) {
                return;
            }
        } catch {
            // not up yet
        }

        await new Promise((resolve) => setTimeout(resolve, 3000));
    }

    throw new Error(`Shop at ${SHOP_URL} did not come up.`);
}

/** The plugin's minimum Shopware version (composer.json). */
const SHOPWARE_VERSION = '~6.7.15.0';

/**
 * Lifts the shop's Shopware packages to the plugin's minimum while
 * requiring the plugin (dockware has no image that new yet), then runs the
 * new version's migrations. Skipped once the plugin is installed.
 */
const INSTALL_PLUGIN = `
    set -e
    cd /var/www/html
    composer config repositories.sw6oidc '{"type": "path", "url": "custom/plugins/Sw6Oidc", "options": {"symlink": true}}'
    if ! composer show martinkuhl/shopware6-oidc-sso >/dev/null 2>&1; then
        packages=$(php -r 'foreach (array_keys(json_decode(file_get_contents("composer.json"), true)["require"]) as $p) { if (preg_match("#^shopware/(core|administration|storefront|elasticsearch)$#", $p)) { echo $p, ":${SHOPWARE_VERSION} "; } }')
        composer require $packages "martinkuhl/shopware6-oidc-sso:*@dev" --with-all-dependencies --no-interaction --no-scripts
        bin/console system:update:finish --no-interaction
        bin/console theme:compile
    fi
    bin/console plugin:refresh
    bin/console plugin:install --activate Sw6Oidc
    bin/console cache:clear
`;

/**
 * Installs the mounted plugin (through composer, so its own dependencies
 * resolve against the shop's) and configures one customer and one admin
 * provider against Dex.
 */
export default async function globalSetup(): Promise<void> {
    await waitForShop();

    shop(INSTALL_PLUGIN);

    // A fresh PHP-FPM, so no worker keeps serving the Shopware version
    // replaced above from its opcache.
    execFileSync('docker', ['compose', 'restart', 'shop'], { cwd: E2E_DIR, stdio: 'inherit' });
    await waitForShop();

    const api = await adminApi();

    // A non-superadmin role and Administration user for admin@example.com:
    // the admin provider links it by verified email (superadmins never are).
    await saveUserEntity(api, 'acl-role', {
        id: E2E_ROLE_ID,
        name: 'E2E editors',
        privileges: ['user:read', 'customer:read', 'sw6oidc_provider:read', 'sw6oidc_provider.viewer'],
    });
    await saveUserEntity(api, 'user', {
        id: E2E_ADMIN_USER_ID,
        username: 'e2e-admin',
        firstName: 'E2E',
        lastName: 'Admin',
        email: ADMIN_EMAIL,
        password: E2E_ADMIN_PASSWORD,
        localeId: await localeId(api),
        admin: false,
        aclRoles: [{ id: E2E_ROLE_ID }],
    });

    const common = {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        wellKnownConfigUrl: `${DEX_URL}/.well-known/openid-configuration`,
        authorizeEndpoint: `${DEX_URL}/auth`,
        accessTokenEndpoint: `${DEX_URL}/token`,
        userInfoEndpoint: `${DEX_URL}/userinfo`,
        jwksEndpoint: `${DEX_URL}/keys`,
        issuer: DEX_URL,
        scope: 'openid profile email',
        pkceFlow: 'S256',
        groupAttribute: 'groups',
        isActive: true,
        requireEmailVerified: true,
        httpTimeout: 15,
        jwksCacheTtl: 3600,
    };

    await upsert(api, 'sw6oidc_provider', [
        {
            ...common,
            id: CUSTOMER_PROVIDER_ID,
            appName: 'dex-customer',
            displayName: 'Dex',
            loginType: 'customer',
            autoCreateCustomer: true,
            showCustomerLink: true,
            disableNonOidcCustomerLogin: false,
        },
        {
            ...common,
            id: ADMIN_PROVIDER_ID,
            appName: 'dex-admin',
            displayName: 'Dex',
            loginType: 'admin',
            autoCreateAdmin: false,
            linkExistingAccounts: true,
            showAdminLink: true,
            disableNonOidcAdminLogin: false,
        },
    ]);

    // Passkeys on for the Administration and every sales channel.
    for (const [key, value] of [['Sw6Oidc.config.passkeyEnabledAdmin', true], ['Sw6Oidc.config.passkeyEnabledCustomer', true]] as const) {
        const response = await api.post('/api/_action/system-config', { data: { [key]: value } });

        if (!response.ok()) {
            throw new Error(`Setting ${key} failed: HTTP ${response.status()}`);
        }
    }

    await api.dispose();
}

async function localeId(api: Awaited<ReturnType<typeof adminApi>>): Promise<string> {
    const response = await api.post('/api/search/locale', {
        data: { filter: [{ type: 'equals', field: 'code', value: 'en-GB' }], limit: 1 },
    });
    const body = await response.json();

    return body.data[0].id;
}
