# Technical Documentation — Shopware 6 OIDC & Passkey SSO

This document is a guided tour for a developer picking up this codebase for the first time. It assumes you know PHP, Symfony-style DI, and OAuth2/OIDC concepts in general, but nothing about this specific plugin or Shopware's plugin conventions.

- For a dense, component-by-component architecture reference once you're oriented, see [CLAUDE.md](CLAUDE.md).
- For admin/end-user setup instructions, see [README.md](README.md) and the IdP-specific guides in [Docs/](Docs/) (Authelia, ZITADEL, Dex).
- For what changed recently, see [CHANGELOG.md](CHANGELOG.md).

---

## 1. Overview

### What it does

This is a Shopware 6.7 plugin (`MartinKuhl\Sw6Oidc`, composer package `martinkuhl/shopware6-oidc-sso`) that adds two independent ways to log in without a Shopware-managed password:

1. **OIDC (OpenID Connect).** Authentication is delegated to an external Identity Provider (IdP) such as Keycloak, Authelia, Okta, Azure AD/Entra, ZITADEL or Dex. It works for **Storefront customers** and **Administration users**. On first login it can create the account (JIT provisioning) and assign customer groups, ACL roles or superadmin based on IdP group claims.
2. **Passkey (WebAuthn/FIDO2).** A separate passwordless method with no IdP involved. The browser's platform authenticator (Face ID, Windows Hello, a security key) signs a challenge and the plugin verifies the signature.

Both paths end the same way. The verified identity goes to Shopware's *native* authentication: a normal sales-channel context on the Storefront, and a real OAuth2 access/refresh token pair in the Administration. Nothing downstream needs to know SSO was involved.

Around these two login paths, the plugin also covers most of the session lifecycle an SSO integration needs:

- logout in both directions (RP-initiated, plus Back-/Front-Channel Logout)
- a session activity log with force-logout
- claims-based access rules
- enforcement of "SSO only, no password login"
- provider health checks with webhook alerting
- config export/import for moving providers between environments

### Why it exists

Shopware ships with password auth only. Organizations with a corporate IdP don't want to manage a separate Shopware password. They also want their central MFA, onboarding and offboarding rules to apply to the shop's admin panel and customer accounts. Passkeys solve a related problem: passwordless, phishing-resistant login for people who aren't routed through a corporate IdP.

The architecture deliberately mirrors the sibling `magento2-oidc-sso` module, so concepts (bindings, role mapping, passkey trade-offs) carry across.

### Project status

This is early-stage software: version `0.1.0` plus a large set of unreleased changes, MIT-licensed, with support for PHP 8.2–8.5 and Shopware `>=6.7.15.0 <6.8.0.0`. Test coverage:

- ~700 unit tests
- an integration suite that runs a real Shopware kernel against Dex
- a browser E2E suite (Playwright against a dockware shop and Dex, `tests/E2E`)

Several items in the `[Unreleased]` changelog section are **breaking** (HTTPS-only IdP URLs, enforced password-login flags, a write-only client secret, `APP_SECRET`-bound encryption, subject-based account binding with `email_verified` required and no automatic linking by email, user verification for passkeys). Read them before upgrading a running shop.

---

## 2. Structure

### Directory layout

```
src/
├── Sw6Oidc.php                 # Plugin bootstrap; only uninstall() is custom (drops tables unless "keep data")
├── Migration/                  # 19 migrations: schema is migration-driven, not install()-driven
├── Core/Content/               # DAL entity definitions (Provider, AttributeMapping, RoleMapping,
│                               #   AccessControlRule, UserProvider, PasskeyCredential, SessionActivity)
│   └── Provider/Field/         #   Sw6OidcEncryptedField: transparent at-rest encryption for secrets
├── Service/
│   ├── Oidc/                   # OIDC protocol: authorize URL, callback pipeline, token exchange, JWT, logout
│   ├── AdminAuth/              # Bridge from verified identity → real Shopware admin OAuth2 tokens; step-up
│   ├── Passkey/                # WebAuthn ceremonies (registration + assertion), relying-party resolution
│   ├── Provisioning/           # Claims → Shopware customer/admin: identity resolution, mapping, transforms, JIT create, sync
│   ├── Security/               # State/PKCE/nonce, browser binding, encryption, SSRF guard, access rules, rate limiter, CSP
│   ├── Session/                # Session registry (DB), IdP-initiated logout, session destruction, activity log
│   ├── Health/                 # Config inspection, reachability probe, alert state machine, webhook, infrastructure warnings
│   ├── Config/                 # Provider export/import (used by the Console commands)
│   ├── Cache/                  # Atomic get-and-delete store for one-time tokens (Redis or a DB table)
│   ├── Http/                   # SSRF-guarded HTTP client factory + OidcHttpClient wrapper
│   ├── Jwt/                    # Unverified payload reader for tokens verified elsewhere
│   ├── Provider/               # Provider lookup (by id, by issuer)
│   └── Logging/                # Dedicated Monolog channel, configurable level, sensitive-data scrubbing
├── Controller/
│   ├── Api/                    # Admin-facing endpoints (/api/sw6oidc/admin/*, incl. step-up; /api/_action/sw6oidc/*)
│   ├── Oidc/                   # Back-/Front-Channel Logout, shared post-logout landing
│   └── HealthCheckController   # GET /sw6oidc/health
├── Storefront/
│   ├── Controller/             # Customer login, "Connect SSO", re-auth, callback, passkey, "My passkeys" page
│   ├── Service/                # Passwordless login route, logout decorator, password-login guard
│   └── EventSubscriber/
├── Subscriber/                 # Write guards (SSRF, lockout, audit log), admin password guard, CSP, account cleanup
├── ScheduledTask/              # State + activity cleanup (daily), health check alerting (5 min)
├── Console/                    # sw6oidc:config:export / sw6oidc:config:import
├── Event/                      # Extension points for integrators (see Section 4)
├── Twig/                       # Injects SSO/passkey buttons and the admin login JS
└── Resources/
    ├── config/                 # services.xml (DI), config.xml (plugin settings), routes.xml
    ├── app/administration/     # Vue: provider module, sessions module, sw-login / sw-profile overrides
    ├── views/storefront/       # Login page buttons, account passkey page
    └── snippet/                # de-DE / en-GB translations
tests/
├── Unit/                       # No Shopware kernel needed
├── Integration/                # Real kernel + Dex (docker-compose.yml), see its README
└── E2E/                        # Playwright: dockware shop + Dex, virtual WebAuthn authenticator, see its README
```

### The three-layer mental model

It helps to think of the code in three layers:

1. **Protocol layer** (`Service/Oidc/`, `Service/Passkey/`). This layer talks to the outside world: the IdP, or the browser's WebAuthn API. It deals in tokens, claims and credentials and knows nothing about Shopware accounts.
2. **Provisioning layer** (`Service/Provisioning/`). This layer turns a verified identity into a Shopware customer or admin. It finds an existing account, enforces the provider binding, creates the account if allowed, maps attributes and resolves groups to roles.
3. **Bridge layer** (controllers, `Storefront/Service/`, `Service/AdminAuth/`). This is the HTTP glue that hands the result to Shopware's real authentication system, where "OIDC/Passkey verified you" becomes a real session or token.

Cross-cutting services sit next to these layers:

- `Service/Security/` guards the edges: SSRF, rate limiting, access rules, password-login policy.
- `Service/Session/` tracks what each login created, so it can be ended later.

Two flows run through the layers: **Storefront/customer** and **Administration/admin**. They share the protocol and provisioning layers almost completely. `OidcCallbackProcessor` is the single callback pipeline for both, "so the two flows can never drift". The bridge layer differs a lot, because customer contexts and admin OAuth2 tokens are fundamentally different mechanisms (see Section 4).

### Data model

| Table | Purpose |
|---|---|
| `sw6oidc_provider` | One row per IdP: credentials (secret encrypted), endpoints, behavior flags, sync toggles, health-alert settings and state |
| `sw6oidc_attribute_mapping` | Per-provider claim → Shopware field, with optional value transform |
| `sw6oidc_role_mapping` | Per-provider OIDC group → ACL role / customer group / superadmin grant |
| `sw6oidc_access_control_rule` | Per-provider claim rules that must all pass before a login is accepted |
| `sw6oidc_user_provider` | Permanent binding: which provider and IdP identity (`issuer`, `sub`, compared byte-exactly) own which account, scoped to a sales channel for channel-bound customers; unique per provider, user type, issuer, `sub` and scope. Written only by the plugin |
| `sw6oidc_passkey_credential` | One row per registered WebAuthn credential (deduplicated by credential-id hash, `disabled_at` after a counter regression) |
| `sw6oidc_session_activity` | Audit log: one row per OIDC/Passkey login, with logout time and reason |
| `sw6oidc_managed_acl_role` | The Administration roles role sync granted (and may take away again) |
| `sw6oidc_session` | Session registry: which local session (context token / access-token `jti`) each OIDC login created, keyed by provider + `sub`/`sid`; session keys and IdP tokens encrypted |
| `sw6oidc_one_time_token` | Atomic one-time tokens when Redis isn't used: flow state, nonces, ceremonies, logout contexts, replay markers (keys hashed, values encrypted) |
| `sw6oidc_node_heartbeat` | Hostnames of app servers that recently handled SSO, for the multi-node warning |

Providers are managed as **DAL entities** through the plugin's own Administration module, **not** through `config.xml`. The plugin settings screen only holds the passkey toggles, RP name/ID and the "Enable debug logging" toggle.

Security state lives in the database, not in cache pools, so `cache:clear`, deploys and evictions can't empty it. One-time tokens go to Redis when `SW6OIDC_REDIS_DSN` is set and usable, otherwise to `sw6oidc_one_time_token`. Only the JWKS cache, the rate-limiter counters and the cached health result use Shopware's cache pools.

### Configuration surface

| Where | What |
|---|---|
| Admin → OIDC provider module | Everything per provider |
| Plugin settings (`config.xml`) | `passkeyEnabledAdmin`, `passkeyEnabledCustomer` (per sales channel), `passkeyRpName`, `passkeyRpId`, `debugLoggingEnabled` |
| `SW6OIDC_LOG_LEVEL` | Base level of the `sw6oidc` channel (default `warning`); the debug toggle raises it to `debug` |
| `SW6OIDC_REDIS_DSN` | Optional `redis://`/`rediss://` for one-time tokens; without it the database store is used |
| `SW6OIDC_HEALTH_TOKEN` | Optional; when set, `/sw6oidc/health` requires it in `X-Sw6oidc-Health-Token` |
| `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1` | Allow http/private-network IdPs (local dev only) |
| `SW6OIDC_ALLOW_PASSWORD_LOGIN=1` | Break-glass: ignore every "disable password login" flag |
| `SW6OIDC_ALLOW_USER_ACCESS_KEYS=1` | Allow `client_credentials` with user access keys while admin password login is disabled |
| `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` | Activity log retention (default 90, `0` = keep forever) |
| `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP=1` | Store activity IPs truncated (IPv4 /24, IPv6 /64) |

---

## 3. Quick Start

### Step 1: Install

```bash
composer require martinkuhl/shopware6-oidc-sso
bin/console plugin:refresh
bin/console plugin:install --activate Sw6Oidc
bin/console cache:clear
```

Installing runs the migrations. On a PHP-FPM host that already runs a shop, also reset opcache after updates (e.g. `cachetool opcache:reset`). Otherwise stale plugin classes can keep being served.

### Step 2: Add a provider

In the Administration, open **OIDC & Passkey SSO** and add a provider:

- **App Name**, **Client ID** and **Client Secret** (or mark it as a public client)
- a **Well-Known Config URL** to auto-discover endpoints, or the endpoints by hand
- **Login Type**: `customer`, `admin` or `both`
- **Auto Create Customer/Admin** if you want JIT provisioning, plus a default customer group or ACL role
- the **Scope** must include `openid`: the callback then requires an `id_token`

IdP URLs must be HTTPS on a public address. For a local IdP, set `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1`.

By default the IdP must send `email_verified: true`, and an existing Shopware account with the same email is **not** taken over: its owner connects it with "Connect SSO" from their account, or you enable **Link existing accounts by verified email** on the provider.

### Step 3: Register redirect URIs at the IdP, then test

Register these at the IdP:

- `https://your-shop.com/sw6oidc/callback` (Storefront)
- `https://your-shop.com/api/sw6oidc/admin/callback` (Admin, also used by "Connect SSO" and SSO step-up in the Administration)
- optionally, `https://your-shop.com/api/sw6oidc/provider/test-callback` for the live login test
- optionally, `https://your-shop.com/sw6oidc/postlogout` as the post-logout URI

Use the **live login test** on the provider detail page first. It runs a real login in a popup, shows the claim keys the IdP returned and previews the access-control result; the claim keys then feed the attribute mapping picker. After that, use the SSO button on the Storefront or Administration login page.

If something is off, switch on **Enable debug logging** in the plugin settings and read `var/log/sw6oidc-<env>.log`. Also run **Run diagnostics** on the provider.

**Passkeys** need no provider setup. Enable them in the plugin settings, and users register a credential from their Storefront account page or the Administration profile.

---

## 4. Functionalities and Use Cases

### OIDC login, Storefront

1. `GET /sw6oidc/login` creates state, a PKCE verifier and a nonce, stores them for 600s in the atomic one-time-token store, sets the browser-binding cookie, and redirects to the IdP. PKCE is always on (`plain` or `S256`). The `redirectTo` target is checked by `RelayStateValidator` (same-site route name or plain absolute path only).
2. `GET /sw6oidc/callback` runs `OidcCallbackProcessor`:
   - consumes the state (single use) and checks the browser-binding cookie, the login type and the flow purpose (`login`, `link`, `step_up`)
   - exchanges the code
   - requires an `id_token` whenever the scope contains `openid`, and verifies it (RS256/384/512 only; key selected by `kid`/`alg`/`use`; 60s leeway on `exp`/`nbf`/`iat`; `iat` required; `azp` checked with several audiences)
   - merges in userinfo claims: userinfo must describe the same `sub`, and `sub`, `email` and `email_verified` always come from the `id_token` when it has them
   - normalizes groups (decoding listed `base64_claims`) and flattens the claims
   - evaluates access-control rules
   - maps the claims to a `MappedProfile`
3. `CustomerProvisioningService` resolves the account through `IdentityResolver` (see "Account binding" below), or creates one. The customer is then logged in **by id**, respecting the customer's sales-channel binding. A JIT-created customer also triggers core's `CustomerRegisterEvent`.

**Use case:** B2B storefronts where customer identity lives in a corporate directory instead of self-service registration.

### OIDC login, Administration

The protocol pipeline is the same, but the bridge is different. The Admin SPA authenticates with OAuth2 tokens, not a server session, so the plugin runs a **second, plugin-owned `league/oauth2-server` instance** wired to Shopware core's *own* client, token and scope repositories. This instance mints genuine tokens via a custom grant (`AdminOidcGrant`). Access- and refresh-token TTLs come from `shopware.api.access_token_ttl` / `shopware.api.refresh_token_ttl`, so SSO sessions follow the shop's normal policy. The grant refuses deleted and inactive users for every caller.

The OIDC redirect is a full-page navigation, so the hand-back to the SPA works like this:

1. The callback stores a 120s nonce, bound to the same browser-binding cookie as the flow.
2. It redirects to `/admin#/login?sw6oidc_nonce=…`.
3. The `sw-login` override POSTs the nonce to `/api/sw6oidc/admin/token` and receives a normal token response, plus a login-session handle that the Administration sends back at logout so exactly that session's registry entry is ended.

**Use case:** staff SSO into the backend with central MFA and offboarding. Removing someone at the IdP removes their shop access.

### Step-up re-authentication (Administration)

Plugin-provisioned admins have a random, unknown password, so core's "confirm your password" dialog (`sw-verify-user-modal`) can't be answered with a password. The plugin extends that dialog with "confirm with SSO / passkey" buttons, backed by `StepUpService` and `/api/sw6oidc/admin/step-up/*`:

- **OIDC:** a round trip to the admin's own bound provider with `prompt=login`, via the admin callback. The `id_token`'s `auth_time` must be after the round trip started, and `sub` must match the admin's binding. IdPs that don't send `auth_time` can't be used for OIDC step-up.
- **Passkey:** an assertion with one of the admin's own passkeys, with user verification.

Either way the result is a short-lived access token with the `user-verified` scope and no refresh token, the same shape core's password confirmation produces. The `user-verified` scope is stripped from every other token request. "Connect SSO" on the own profile and admin passkey registration require such a token.

**Inactivity re-login.** The inactivity modal offers one SSO button per admin provider and the passkey button, returns the admin to the page they were on, and refuses or skips a login as a *different* admin.

### Passkey login

A user registers a device credential once, while logged in, and then signs in with a fingerprint, face, PIN or security key. The plugin stores and verifies the credential itself.

- User verification is **required** for registration and login.
- Login is usernameless (discoverable credentials) on both the Storefront and the Administration; the Administration never lists an account's credentials to anonymous callers.
- The relying party comes from configuration, never from the `Host` header: the Administration uses the origin of `APP_URL`, the Storefront the current sales channel's domains. The RP ID is that host unless `passkeyRpIdAdmin` (Administration) or `passkeyRpId` (per sales channel) is set; both must be the host or a parent domain and are checked on save. Allowed origins are checked exactly, without subdomains.
- A login ceremony only completes for the purpose it was started for (Storefront channel, Administration login, one admin's step-up).
- A registration completes only for the account that started it. Customers need a freshly authenticated *browser session* (a login of any kind, or a verified re-authentication, within 10 minutes; `/sw6oidc/reauth` sends them through one); admins need a `user-verified` token.
- Deleting a passkey ends the sessions it logged in: exactly those Store API contexts for a customer, all sessions for an admin.
- Credential rows are written by the plugin only; the Admin API can rename or delete them, nothing else.
- A signature counter that goes backwards disables the credential.
- Every passkey endpoint answers 404 while passkeys are disabled for that user type.
- Admin passkey login uses `AdminOidcGrant` directly, because it's a same-page AJAX ceremony and needs no nonce.
- A new passkey dispatches `PasskeyRegisteredEvent` (audit log entry, Flow Builder trigger `sw6oidc.passkey.registered`).

**Use case:** phishing-resistant, password-free login without a corporate IdP, or a second option alongside OIDC.

### JIT provisioning, mapping and sync

**Attribute mapping** covers 19 target fields (identity plus billing and shipping address). Only the identity fields have OIDC-standard default claims. Address fields stay unmapped until you configure them.

Each mapping can apply a **transform**:

- `concat`
- `split`
- `prefix`
- `regex_replace` (the pattern is validated on save)

A failing transform passes the raw value through and logs a warning, except on `email` and `username`, where it fails the login. Birthdates are only taken in strict `Y-m-d` form between 1900 and today.

**Group mapping** resolves the groups claim to ACL roles (every matching row) or a customer group (the first match by `sort_order`). The provider defaults apply only when an account is created.

**Superadmin** is opt-in behind two gates: the provider flag `allow_superadmin_group_mapping` **and** an explicit `superadmin` mapping row. A stray row alone never grants it.

**Sync-on-SSO** re-applies claims on every login. Five independent per-provider toggles control it (customer profile, address, group; admin profile, role). Profile and address sync are partial updates: unmapped values are left alone and never reset. Admin role sync adds every mapped role and removes the roles it granted earlier that no group grants any more; roles granted by hand in Shopware are never touched. Customer group sync only changes the group when a mapping matches. Superadmin is only revoked with the opt-in `revoke_superadmin_on_sso` (also when no group resolves), and never from the last active superadmin.

First logins create and bind the account in one transaction; two concurrent first logins end up in the same account. JIT customers follow Shopware's "bind customers to sales channel" rule, and a customer created with placeholder addresses is sent to the address form before checkout.

**Use case:** onboarding happens entirely on the IdP side. Add someone to "Engineering" there, and their first login creates a Shopware admin with the right role.

### Account binding

`IdentityResolver` decides which account an IdP identity logs into, for customers and admins alike. Accounts are bound to the provider **and the IdP subject** (`sw6oidc_user_provider.issuer`/`sub`); the email claim alone is never proof of ownership.

1. With `require_email_verified` (default on), the login is refused unless `email_verified` is `true` and the mapped email is the standard `email` claim. A transformed or custom-claim email mapping is refused at save time while verification is required.
2. An account bound to this provider, issuer and subject logs in (in the sales channel's scope first for channel-bound customers, then globally).
3. A legacy binding (from before subjects were stored) of the email-matched account to this provider is upgraded with the subject, only with a verified email and never for an Administration user.
4. An unbound account with the same email is linked only when the provider has `link_existing_accounts` on (default off), the email is verified and the account is not an Administration user. Otherwise the login is refused with "connect explicitly".
5. No account: the caller may JIT-create one.

A binding to another provider fails with `ProviderMismatchException`; the same provider with a different subject is refused too. Concurrent first logins don't fail on the unique keys.

**"Connect SSO"** is the explicit way to bind an existing account: a logged-in customer starts it from the account profile (`POST /sw6oidc/link`, needs a freshly authenticated browser session), an admin from their own profile with a `user-verified` token (`/api/sw6oidc/admin/link/start`). The callback binds the IdP identity to exactly that account and dispatches `AccountSsoLinkedEvent` (Flow Builder trigger `sw6oidc.account.sso_linked`, mail-aware). It is the only way to bind an Administration user that already exists.

Admins can unlink a binding from the user or customer detail page; unlinking an admin needs a `user-verified` token and can't remove the last way into an SSO-only Administration.

**Changing a provider's issuer** with bound accounts needs a superadmin's decision: keep them connected (same IdP under a new URL) or disconnect them (another tenant; its users never log into these accounts).

### Access control rules

Per-provider rules on flattened claims. All rules must pass, and they're evaluated before any account lookup or creation. A claim's values are its members when it is a list or object (list entries, or role-object keys), else its scalar value.

| Operator | Passes when |
|---|---|
| `eq` | any value equals the expected value |
| `neq` | the claim is present and no value equals it |
| `contains` | a member equals it; on a scalar, one of its whitespace- or comma-separated tokens equals it (never a substring) |
| `not_contains` | the claim is present and `contains` is false |
| `ends_with` | any value ends with the expected suffix |
| `email_domain` | any value is a valid email address whose domain is exactly the expected one (leading `@` ignored) |
| `exists` / `not_exists` | the key or any child key is present / absent |

- The negative operators **deny** when the claim is missing, so an omitted claim can't skip a deny rule.
- Matching is case-insensitive and trimmed; `true`/`1` and `false`/`0` compare as equal. The operator is a strict choice on write, and an unknown operator fails closed.
- Each rule can carry its own denial message.
- The Admin login screen receives the message through a one-time error ticket, so free text never goes into a URL.

**Use case:** "only `department=sales` may log in through this provider", without touching IdP client config.

### "SSO only": disabling password login

`disable_non_oidc_{admin,customer}_login` turns off password login for that user type:

- **Admin:** a decorator of core's OAuth `UserRepository` treats every username/password pair as invalid, and a decorator of core's `ClientRepository` refuses user access keys (unless `SW6OIDC_ALLOW_USER_ACCESS_KEYS=1`), however the token request is encoded. The token-request listener adds a 403 in front and refuses undeterminable grant types.
- **Customer:** Storefront and Store API password login, registration and double-opt-in confirmation are refused; guest checkout stays allowed. The login and register forms are hidden.

Guards, checked on the *result* of every write that can change it (provider save or delete, user deactivation or deletion, admin unlink, issuer change):

- While Administration password login is off, at least one active admin stays bound to an active provider that serves admin logins — whichever field changes, re-activation and re-scoping included.
- The login page must keep showing an SSO button; customer password login needs at least one bound customer of the provider.
- Turning admin password login off while other active admins have no SSO binding needs the acting admin's confirmation with a fresh re-authentication (CLI writes count as confirmed).
- Turning it off ends the sessions of accounts without any binding (they can only be password sessions), from the message queue; guest checkouts are kept.

The break-glass override is `SW6OIDC_ALLOW_PASSWORD_LOGIN=1`.

### Logout, in both directions

**Shop → IdP (RP-initiated).** Storefront and Admin logout redirect to the IdP's `end_session_endpoint` and revoke the login's IdP access and refresh tokens (RFC 7009, fire-and-forget). The Store API logout returns the IdP logout URL as `redirectUrl`. Admin logout ends exactly the logging-out session's registry entry; without an exact match nothing is removed from the registry.

- The provider's **logout style** decides the format: standard OIDC RP-Initiated Logout (`client_id`, `id_token_hint`, `post_logout_redirect_uri`, `state`) or Authelia's portal logout (`?rd=`).
- For IdPs that allow only one post-logout URI, `/sw6oidc/postlogout` routes customers and admins using an HMAC-signed `state`.

**IdP → shop.**

- `POST /sw6oidc/backchannel-logout` accepts a fully verified logout token: signature, `iss`/`aud`/`exp`, a back-channel `events` member, `sub` and/or `sid`, no `nonce`, a required `jti` (replay marker via atomic set-if-absent) and a required `iat` no older than 5 minutes (plus 60s leeway). Anonymous callers only ever see a fixed `invalid_request`; a correctly signed token is never refused by the rate limiter.
- `GET /sw6oidc/frontchannel-logout?iss=&sid=` handles iframe-based logout and always returns a 1×1 GIF. It ends **admin** sessions only when the provider has `frontchannel_admin_logout` on, because the request is unauthenticated and admin sessions can only be ended all at once. Customer sessions are always ended.

Both endpoints look sessions up in the **session registry** (`sw6oidc_session`), which records the context token or access-token `jti` each OIDC login created, keyed by provider plus `sub` and `sid`. IdP-initiated admin logout clears all of that admin's registry entries.

### Session activity log and force logout

Every OIDC or Passkey login writes a row to `sw6oidc_session_activity`. The row records provider, IP (optionally truncated with `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP=1`), user agent, login and logout time, and logout reason (`logout`, `backchannel`, `frontchannel`, `forced`). The fields are write-protected and API deletes are refused; `sub`/`sid` are not exposed through the API.

The **OIDC & Passkey sessions** Admin module lists these rows and offers **Force logout**, behind the `sw6oidc_session_activity:force_logout` privilege. The daily cleanup task prunes old rows in batches, together with expired registry entries, one-time tokens and heartbeats.

Deleting a user or customer removes its binding, passkeys, registry entries and activity rows. Deactivating one ends all of its sessions.

Auditing never blocks a login or logout: every recorder method swallows and logs its own errors.

### Health checks and alerting

- **`GET /sw6oidc/health`** is for uptime monitors. It makes no outbound calls and reports counts and warning codes only, cached for 30 seconds. `status` is `ok`, `degraded` (some provider incomplete or its monitored probe failed), `down` (no active provider usable; HTTP 503) or `unconfigured`. Only providers with alerting configured count their probe result, and results older than 15 minutes count as `unknown`. With `SW6OIDC_HEALTH_TOKEN` set, the `X-Sw6oidc-Health-Token` header is required (401 otherwise).
- **Infrastructure warnings** (`infrastructure.warnings` in the health response, also shown by **Run diagnostics**): `redis_dsn_unusable` (the DSN is set, but Redis isn't used) and `multi_node_without_redis` (more than one app server handled SSO in the last 15 minutes, per `NodeHeartbeat`, and Redis isn't in use). Warnings never change the status.
- **Run diagnostics** on a provider checks config completeness, shows the one-time-token store and runs a live JWKS/discovery probe.
- **Scheduled alerting** runs every 5 minutes. After N consecutive failures it POSTs one webhook alert per outage, with an optional recovery message. The webhook URL is encrypted and SSRF-checked; failures are logged with class and code only.

### Security hardening you get for free

- **SSRF protection.** Every IdP URL is checked on save (HTTPS, public IPs only), and `NoPrivateNetworkHttpClient` re-checks every connection at runtime. The plugin's HTTP client follows no redirects by default; only GET requests are retried. Avatars are fetched through the same client. Changing an endpoint URL requires entering the client secret again.
- **Encrypted secrets.** Client secrets, webhook URLs and stored security state are encrypted at rest. Envelope v2 (`sw6oidc_v2:`) is XChaCha20-Poly1305 with a key derived per purpose from `APP_SECRET` and the purpose as associated data; v1 envelopes are still read, and a migration re-encrypts stored provider secrets. Secrets are write-only over the Admin API, blanked in written events, and never sent to the IdP as an envelope.
- **Browser binding.** An HttpOnly, SameSite=Lax cookie (`__Host-` on HTTPS) ties every flow and admin login nonce to the browser that started it, against login CSRF.
- **Rate limiting.** Per client IP (IPv6 per /64), per endpoint scope. Endpoints that create state on success (flow start, passkey options) have a consuming budget of 30 requests per minute; redeem endpoints (callbacks with a valid state, nonce exchange, passkey verify, error tickets, step-up, logout tokens) count only failures, 10 per minute. Callbacks with an unknown state aren't counted. Behind a proxy or CDN, `framework.trusted_proxies` must be configured, or all clients share one budget.
- **Logging.** `SensitiveDataProcessor` masks credential keys and sensitive query parameters; the log file rotates daily (14 files).
- **CSP.** IdP origins are appended to CSP directives the shop already declares (including Report-Only headers). The plugin never adds a directive.

### Operations: config export/import

```bash
bin/console sw6oidc:config:export -o providers.json
bin/console sw6oidc:config:import -i providers.json --dry-run
```

The export is versioned JSON covering providers, mappings and access rules. ACL roles and customer groups are resolved by id, then by unique name. `-o` creates the file exclusively with mode 0600; `--force` overwrites an existing one.

The secret is omitted by default. `--keep-encrypted` keeps the stored envelope, which only imports where `APP_SECRET` is identical. `--plaintext` exports the decrypted value. `--overwrite` on import replaces only the child collections and default references present in the file, and warns about missing ones.

**Use case:** promoting a tested provider setup from staging to production.

### Extension points (`src/Event/`)

| Event | When | What you can do |
|---|---|---|
| `AttributeMappingCompletedEvent` | After mapping, every OIDC login | Replace the `MappedProfile` (email is re-validated afterwards) |
| `CustomerBeforeCreateEvent` / `AdminBeforeCreateEvent` | Just before JIT create | Change the create payload |
| `CustomerAfterCreateEvent` / `AdminAfterCreateEvent` | After create + binding | React (read-only); not fired for existing accounts |
| `PasskeyRegisteredEvent` | After a passkey was registered | Flow Builder trigger, audit log entry |

`AdminBeforeCreateEvent` can set `admin` and `aclRoles`. A listener can therefore bypass the two-gate superadmin rule. This is intentional power, so treat such listeners as security-sensitive code. Such grants and role changes are logged as warnings, and a changed email is reverted to the verified claim.

### What it deliberately is not

It is an OIDC **client**, not an OAuth2 provider for third parties. It doesn't replace password login unless you set the per-provider "disable" flags, so SSO and passwords coexist by default. Passkey attestation is `none`: the plugin favors broad device compatibility over verifying authenticator provenance.

---

## 5. Gotchas: edge cases, limitations, and things that will bite you

### Keep `APP_SECRET` stable

The key that encrypts client secrets, webhook URLs and stored security state (registry entries, one-time tokens) is derived from `APP_SECRET`. If you rotate it, entities still load, but `getUsableClientSecret()` returns nothing, `TokenExchangeService` throws `ClientSecretUnavailableException`, and every provider's secret has to be entered again.

The same applies to `--keep-encrypted` exports: they only import into an installation with the identical `APP_SECRET`. A short `APP_SECRET` (e.g. from a template) also breaks admin token signing in tests.

Envelopes are bound to their purpose (e.g. `sw6oidc_provider.client_secret`). Copying an encrypted value between columns or tables makes it undecryptable on purpose.

### State, PKCE and nonce are genuinely single-use

The flow context is read with an atomic get-and-delete. Re-hitting a callback URL after a successful **or failed** first attempt always fails with `InvalidStateException`. When debugging, restart from `/sw6oidc/login`. Don't replay the callback.

The flow is also bound to the browser that started it. A callback opened in another browser or profile, or after the browser-binding cookie was deleted, fails.

### One-time tokens: Redis or database

Without `SW6OIDC_REDIS_DSN`, one-time tokens live in `sw6oidc_one_time_token` (`SELECT … FOR UPDATE` + delete in one transaction). That is atomic and shared by all app servers, so Redis is optional. With Redis, reads use a GET+DEL Lua script and replay markers `SET … NX EX`.

The backend is selected **at runtime** on purpose, not in a compiler pass, so the choice isn't frozen into the cached container and changing the variable needs no cache clear. Redis errors fall back to the database per call, and an unreachable Redis is marked down for 30 seconds. An unusable DSN shows up as `redis_dsn_unusable` in the health endpoint and diagnostics.

On several app servers without Redis, logins stay correct, but the rate limiter and the JWKS cache are per node unless Shopware's cache pools are shared. The health endpoint reports this as `multi_node_without_redis`.

### Order matters: normalize groups *before* flattening claims

`OidcCallbackProcessor` normalizes the raw groups claim before it calls `ClaimsNormalizer::flatten()`. ZITADEL sends roles as nested objects (`{"Engineering": {"orgId": "…"}}`). Flattening first would turn the group names into dotted paths like `roles.Engineering.orgId` and lose them. Keep this order if you touch claim handling.

`base64_claims` is applied in both places: a listed name covers the claim and everything nested under it, `*` covers all claims. Groups are decoded only when the group attribute is listed.

Flattening also has limits: depth 5 and 2000 keys, beyond which it throws `ClaimsTooComplexException`.

### `AdminOidcGrant` trusts its caller completely

The grant has no password or credential check. It reads a pre-verified user id from a PSR-7 request attribute and issues a token (only refusing deleted or inactive users). That's safe only because every caller verifies the user first, via a JWT-verified OIDC login, a verified WebAuthn assertion or a completed step-up. If you add a caller, you own that verification.

### Never alias the plugin's OAuth2 server to the League class id

`AdminAuthorizationServerFactory` registers the server under the plugin's own service id. Shopware core already has its own `League\OAuth2\Server\AuthorizationServer` for `/api/oauth/token`. A "cleanup" that aliases the bare class id breaks one of the two.

Admin passkey login must also set `client_id=administration` on the request manually. League validates the client before the grant's `validateUser()` runs.

### Admin sessions can't be ended individually from outside

Shopware admin access tokens are stateless JWTs, and revoking one is a no-op in core. Refresh-token ids also rotate on every refresh. So force logout and Back-/Front-Channel Logout for an **admin** end **all** of that admin's sessions. They do this by revoking all refresh tokens and bumping `user.last_updated_password_at` (the password itself is untouched). Customers, by contrast, lose exactly the one affected context. The admin's own logout is different: core ends the local session, and the plugin removes only that session's registry entry (matched by the login-session handle or the current `jti`).

### The session registry only knows what it saw

IdP-initiated logout only finds sessions of OIDC logins recorded in `sw6oidc_session`. Passkey logins are never registered, because there's no IdP session. Entries live as long as core still has the session (admins: an unexpired refresh token; customers: a context used within `shopware.api.store.context_lifetime`), at most 90 days, and are pruned daily. Sessions created before the registry moved to the database aren't known.

### Passkeys are bound to one domain

A passkey is cryptographically bound to one Relying Party ID, which is effectively the domain. Changing `passkeyRpId`/`passkeyRpIdAdmin`, `APP_URL` (Administration) or the sales channel's domains (Storefront) can invalidate registered passkeys, and users must register again. Origins are pinned exactly: a domain that isn't the RP ID or below it is dropped for that ceremony.

### webauthn-lib 5.x: you own credential lookup and persistence

webauthn-lib 5.x has no repository contract. `PasskeyAuthenticationService` loads the `CredentialRecord` itself and must persist what `check()` returns via `updateAfterAssertion()`. If that step is skipped, signature-counter replay detection (which disables the credential on a regression) is silently disabled.

The ceremony state holds **raw inputs**, not serialized options. The options are rebuilt on verify. This started as a workaround for a 4.x base64 bug and was kept because it doesn't depend on symmetric (de)serialization.

### "Disable password login" is shop-wide

`PasswordLoginPolicy` returns true if *any* active provider serving that login type has the flag set. Providers aren't sales-channel scoped, so one provider's flag disables password login for every sales channel.

Superadmin revocation is opt-in: `sync_admin_role_on_sso` grants superadmin on a matching group, but only revokes it with `revoke_superadmin_on_sso`, and never from the last active superadmin. This avoids a claims glitch locking out the only superadmin.

### OIDC step-up needs `auth_time`

`StepUpService` refuses an OIDC step-up when the `id_token` has no `auth_time`, or one from before the round trip started. IdPs that ignore `prompt=login` or omit `auth_time` (Dex, for example) can only use passkey step-up. The E2E suite skips the OIDC step-up test for that reason.

### `OidcCustomerLoginRoute` is not a decorator, on purpose

`OidcCustomerLoginRoute` extends `AbstractLoginRoute`, but its `getDecorated()` throws. This keeps the real login route doing password checks for everyone else, while `PasswordLoginGuardLoginRoute` separately decorates the core route to enforce the disable flag.

Storefront logout needs two classes, a route decorator and a response subscriber. A `CustomerLogoutEvent` listener can't work, because core swaps the context token *before* it dispatches that event.

### The admin login JS reload is load-bearing

After the nonce exchange, the `sw-login` override forces a router push and sometimes a full reload. Without it, a login that didn't come from core's own component leaves the SPA's modules and menu uninitialized, and the dashboard stays blank. The E2E suite covers this regression.

`AdminEntrypointsExtension` exists for a related reason. Shopware normally skips plugin JS on the pre-auth login screen, so this Twig extension loads the plugin's admin bundle there explicitly. A missing or unparsable `entrypoints.json` degrades gracefully.

### Logging

The `sw6oidc` channel logs at `SW6OIDC_LOG_LEVEL` (default `warning`). The **Enable debug logging** plugin setting raises it to `debug` without a deploy; `ConfigurableLevelHandler` reads it once per request (reset between requests in long-running workers). Debug logs contain claim keys and more personal data even with masking, so switch the toggle off after troubleshooting.

### Smaller traps

- **Missing nonce.** If no nonce was expected, `JwtVerifier` logs a warning and *skips* the nonce check instead of failing.
- **No `openid` scope.** With `openid` in the scope, a missing `id_token` fails the login. Without it, the flow relies on userinfo alone and logs a warning; `email_verified` then has to come from userinfo.
- **Custom email claim.** An email mapped from a claim other than `email` is never considered verified, so with `require_email_verified` on such logins fail.
- **Placeholder addresses.** Customers created without address claims get `-` placeholders in the billing address (no zipcode placeholder), flagged with the `sw6oidc_placeholder_address` custom field. Address sync only updates the existing default billing address and never creates one.
- **Unresolvable hosts.** The write guard blocks unresolvable hosts even in insecure mode. Test fixtures need resolvable hostnames or IP literals.
- **Front-channel logout.** It needs both `iss` and `sid`, because SameSite cookies never reach a cross-site iframe, and it leaves admin sessions alone unless `frontchannel_admin_logout` is on.
- **Live login test.** It needs `sw6oidc_provider:update`, stores claim keys only, and previews the access-control result without logging anyone in.
- **Trusted proxies.** Without `framework.trusted_proxies`, every client behind a proxy or CDN shares the proxy's IP and its rate-limit budget.

### Test coverage and its blind spots

- **Unit tests** (`composer test`, no kernel) cover the OIDC core, provisioning, WebAuthn ceremonies against the real 5.x validators, and every security component.
- **Integration tests** (`SHOPWARE_PROJECT_ROOT=/path/to/shop composer test-integration`) run a real kernel and database with Dex (`tests/Integration/docker-compose.yml`). They cover Back-Channel Logout, full Storefront and Admin OIDC logins, and access rules. They must use the **shop's** PHPUnit and autoloader, because the plugin's own `vendor/` contains a second `shopware/core`. `tests/Integration/README.md` has the setup details.
- **E2E tests** (`tests/E2E`, Playwright) run against a dockware Shopware 6.7 shop with the plugin mounted and Dex. They cover Storefront and Admin SSO login/logout, the nonce hand-off and blank-dashboard regression, SSO-only mode, customer passkey registration and login, admin step-up (password, passkey, OIDC) and inactivity re-login, with WebAuthn via Chromium's virtual authenticator. The CI `e2e` job is non-blocking for now. `tests/E2E/README.md` has the setup details.

None of the suites covers:

- quirks of real IdPs other than Dex
- browsers other than Chromium

After you change controllers, `services.xml`, templates or Vue code, run the E2E suite or do a manual login round-trip: Storefront and Admin, OIDC and Passkey. The committed storefront `dist` bundle must be rebuilt after Storefront JS changes; the CI `assets` job fails on a stale one.

`composer ci` runs the same gates as CI: PHPCS, PHPStan level 5, Psalm level 4, Rector dry-run, then unit tests.

---

## 6. Future Improvements

Roughly in order of risk reduction per unit of effort:

1. **Add an `APP_SECRET` rotation command.** For example, `sw6oidc:secrets:reencrypt --old-secret=…` would re-encrypt stored secrets, instead of every provider's secret having to be re-entered.
2. **Make admin session termination granular.** Tracking refresh-token lineage per login (or storing session ids in a custom token claim) would let force logout and Back-Channel Logout end one admin session instead of all of them. The same work would close the passkey tracker's refresh gap.
3. **Scope providers and password-login flags per sales channel.** Today one provider's flag affects every sales channel. Multi-brand shops will eventually want per-channel control.
4. **Support optional passkey attestation.** An opt-in attestation policy with an allow-list (MDS/AAGUID) would help admin accounts in regulated environments.
5. **Add a dev environment.** A committed docker-compose Shopware setup would give new contributors a disposable shop instead of a personal staging install. `tests/E2E/docker-compose.yml` (dockware shop + Dex) is a starting point.
6. **Prepare for Shopware 6.8.** The plugin pins `<6.8`. The admin overrides (`sw-login`, `sw-inactivity-login`, `sw-profile`, `sw-verify-user-modal`) and the second League server are the parts most likely to break on a major upgrade, so they're the first places to check.
