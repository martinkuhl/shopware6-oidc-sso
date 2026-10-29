import { chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { adminApi, saveUserEntity, upsert } from '../support/admin-api';
import { dexLogin } from '../support/dex';
import {
    ADMIN_EMAIL,
    ADMIN_PROVIDER_ID,
    CLIENT_ID,
    CLIENT_SECRET,
    CUSTOMER_PROVIDER_ID,
    DEX_URL,
    E2E_ADMIN_PASSWORD,
    E2E_ADMIN_USER_ID,
    E2E_ADMIN_USERNAME,
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
 * Settings the web requests need too. PHP-FPM doesn't pass the container's
 * environment (docker-compose.yml) to PHP, so they go into the shop's env
 * file: the compiled .env.local.php when the shop has one (Symfony then
 * ignores the .env files), else .env.local.
 */
const SHOP_ENV: Record<string, string> = {
    // Dex is plain HTTP on a private network address: dev-only escape hatch.
    SW6OIDC_ALLOW_INSECURE_IDP_URLS: '1',
    SW6OIDC_LOG_LEVEL: 'debug',
};

const WRITE_SHOP_ENV = `
    php -r '
        $vars = json_decode($argv[1], true);
        if (is_file(".env.local.php")) {
            file_put_contents(".env.local.php", "<?php return " . var_export(array_merge(require ".env.local.php", $vars), true) . ";\\n");
        } else {
            $lines = is_file(".env.local") ? file(".env.local", FILE_IGNORE_NEW_LINES) : [];
            $lines = array_filter($lines, fn ($l) => !array_key_exists(explode("=", $l, 2)[0], $vars));
            foreach ($vars as $k => $v) { $lines[] = $k . "=" . $v; }
            file_put_contents(".env.local", implode("\\n", $lines) . "\\n");
        }
    ' '${JSON.stringify(SHOP_ENV)}'
`;

/**
 * Lifts the shop's Shopware packages to the plugin's minimum while
 * requiring the plugin (dockware has no image that new yet), then runs the
 * new version's migrations. Skipped once the plugin is installed.
 */
const INSTALL_PLUGIN = `
    set -e
    cd /var/www/html
    ${WRITE_SHOP_ENV}
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

    // A non-superadmin role and Administration user for admin@example.com,
    // connected to Dex below (no admin is ever linked by email alone).
    await saveUserEntity(api, 'acl-role', {
        id: E2E_ROLE_ID,
        name: 'E2E editors',
        // What the role editor saves for "SSO providers: viewer" plus
        // "Update own profile" (the passkey profile tab's route privilege):
        // the role keys, their expanded privileges (acl/index.js, core's
        // sw-profile acl) and core's defaults (privileges.service
        // getRequiredPrivileges()), else the pages' own requests get 403s.
        privileges: [
            'sw6oidc_provider.viewer',
            'user.update_profile',
            'user_change_me',
            'user_config:read',
            'user_config:update',
            'user_config:create',
            'sw6oidc_provider:read',
            'sw6oidc_attribute_mapping:read',
            'sw6oidc_role_mapping:read',
            'sw6oidc_access_control_rule:read',
            'acl_role:read',
            'customer_group:read',
            'user:read',
            'customer:read',
            'language:read',
            'locale:read',
            'message_queue_stats:read',
            'log_entry:create',
            'currency:read',
            'country:read',
            'scheduled_task:read',
        ],
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

    await connectE2eAdminToDex();
}

/**
 * "Connect SSO" for e2e-admin, as the admin does it from the profile: a
 * user-verified token starts a link round trip, Dex confirms the identity.
 * The plugin never links an existing admin by email (R3-M10), and linking the
 * same identity again is a no-op, so this runs on every setup. The browser
 * context's request client shares its cookies with the page, so the
 * browser-binding cookie set by link/start reaches the callback.
 */
async function connectE2eAdminToDex(): Promise<void> {
    const browser = await chromium.launch();

    try {
        const context = await browser.newContext({ baseURL: SHOP_URL });
        const tokenResponse = await context.request.post('/api/oauth/token', {
            data: {
                grant_type: 'password',
                client_id: 'administration',
                scope: 'user-verified',
                username: E2E_ADMIN_USERNAME,
                password: E2E_ADMIN_PASSWORD,
            },
        });

        if (!tokenResponse.ok()) {
            throw new Error(`e2e-admin login failed: HTTP ${tokenResponse.status()} ${await tokenResponse.text()}`);
        }

        const { access_token: token } = await tokenResponse.json();
        const startResponse = await context.request.post('/api/sw6oidc/admin/link/start', {
            data: { providerId: ADMIN_PROVIDER_ID },
            headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        });

        if (!startResponse.ok()) {
            throw new Error(`Starting the SSO link failed: HTTP ${startResponse.status()} ${await startResponse.text()}`);
        }

        const { authorizeUrl } = await startResponse.json();
        const page = await context.newPage();
        await page.goto(authorizeUrl);
        await dexLogin(page, ADMIN_EMAIL);
        // The Administration (success or error), not the callback on its way.
        await page.waitForURL(/\/admin\/?#/, { timeout: 30_000 });

        if (!page.url().includes('sw6oidc_linked=1')) {
            throw new Error(`Connecting e2e-admin to Dex failed, landed on ${page.url()}`);
        }
    } finally {
        await browser.close();
    }
}

async function localeId(api: Awaited<ReturnType<typeof adminApi>>): Promise<string> {
    const response = await api.post('/api/search/locale', {
        data: { filter: [{ type: 'equals', field: 'code', value: 'en-GB' }], limit: 1 },
    });
    const body = await response.json();

    return body.data[0].id;
}
