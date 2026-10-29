# Browser E2E tests

Playwright drives a real Shopware 6.7 shop (dockware, plugin mounted) and Dex
as the identity provider. WebAuthn runs against Chromium's virtual
authenticator (CDP), with user verification and resident keys.

## Run locally

```bash
cd tests/E2E
echo "127.0.0.1 dex" | sudo tee -a /etc/hosts   # browser and shop share Dex's issuer URL
npm install
npx playwright install chromium
npm run env:up       # shop on http://localhost, Dex on http://dex:5556
npm test
npm run env:down
```

`SW6OIDC_E2E_SHOP_IMAGE` overrides the shop image (default
`dockware/shopware:6.7.14.2`); `SW6OIDC_E2E_SHOP_URL` the shop URL.

The global setup installs the mounted plugin through composer (so its
dependencies resolve against the shop's). The plugin needs Shopware 6.7.15,
for which dockware has no image yet, so the same `composer require` lifts the
shop's Shopware packages to `~6.7.15.0` (then `system:update:finish` and a
container restart). Once a 6.7.15 image exists, switch the default image and
this step is skipped by composer. `SW6OIDC_ALLOW_INSECURE_IDP_URLS` and
`SW6OIDC_LOG_LEVEL` are also written to the shop's `.env.local` (or
`.env.local.php`): PHP-FPM doesn't pass the container environment to web
requests. The setup then creates a customer and an
admin provider, a non-superadmin `e2e-admin` with `admin@example.com`, and
switches passkeys on. It is idempotent.

## Specs

| Spec | Covers |
|---|---|
| `01-storefront-oidc` | SSO login/logout, redirect target kept across the round trip |
| `02-admin-oidc` | Admin SSO login, nonce hand-off, no blank dashboard after reload, forged nonce |
| `03-sso-only` | Password form hidden; Store API password login and registration refused |
| `04-customer-passkey` | Registration after a fresh login, passkey login |
| `05-admin-step-up-and-passkey` | Re-confirmation before registering, password and passkey step-up, OIDC step-up (skipped when Dex sends no `auth_time`), inactivity re-login refuses a foreign passkey |

Specs run in order with one worker; they share one shop.

## CI

The `e2e` job in `.github/workflows/ci.yml` runs this suite and uploads the
report as the `playwright-report` artifact. On failure the artifact also holds
the shop's logs (`shop-logs/`: container, Shopware, the plugin's `sw6oidc`
log), which say why a login was refused.
