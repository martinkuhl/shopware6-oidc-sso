# Integration test suite

Runs the plugin inside a real Shopware 6.7 kernel and database, against
[Dex](https://dexidp.io/) as a real OpenID Connect provider. Separate from the
unit suite (`composer test`), which needs neither.

| Test | Needs Dex | Covers |
|---|---|---|
| `BackChannelLogoutTest` | no | `POST /sw6oidc/backchannel-logout` through routing, `JwtVerifier`, the session registry and the context persister (the JWKS is seeded into `cache.app`; Dex can't send logout tokens) |
| `StorefrontOidcLoginTest` | yes | Storefront login end to end: authorize redirect, Dex login, callback, token exchange, id_token verification, JIT customer, registry + activity log; replayed callback rejected |
| `AdminOidcLoginTest` | yes | Administration login end to end, including the nonce hand-off and a working Shopware admin access token |
| `AccessControlRulesTest` | yes | Claims-based access control against Dex's real claims |

Tests that need Dex are skipped when it isn't reachable.

## Running it

1. A Shopware 6.7 installation whose `composer.json` requires this plugin
   through a path repository, with `APP_URL=http://localhost:8000` (the Dex
   client in `dex/config.yaml` only accepts redirect URIs on that origin), and
   the test dependencies in *its* `vendor/`:

   ```bash
   composer require --dev phpunit/phpunit:^11.5 symfony/browser-kit
   ```

   The suite runs with the shop's PHPUnit and autoloader, not the plugin's
   `vendor/` (which has its own copy of `shopware/core` and would clash).
   Shopware's `TestBootstrapper` creates a separate `<database>_test` database
   on first run and installs the plugin there — your shop's data is not touched.
2. Start Dex:

   ```bash
   docker compose -f tests/Integration/docker-compose.yml up -d --wait
   ```

3. Run the suite from the plugin directory (the script calls
   `$SHOPWARE_PROJECT_ROOT/vendor/bin/phpunit`):

   ```bash
   SHOPWARE_PROJECT_ROOT=/path/to/shopware composer test-integration
   ```

`phpunit.integration.xml.dist` sets `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1`,
because Dex runs on plain HTTP on loopback — never set that in production.

The CI job `shopware` in `.github/workflows/ci.yml` runs the suite on every
push and pull request against a fresh `shopware/production` 6.7 project. It
writes the shop's test settings to `.env.test.local`, because Dotenv ignores
`.env.local` when `APP_ENV=test`.
