# Shopware 6 OIDC & Passkey SSO

<p align="center">
  <img src="src/Resources/config/plugin.png" alt="Sw6Oidc Logo" width="160" />
</p>

OpenID Connect (OIDC) and Passkey (WebAuthn) single sign-on for Shopware 6 Storefront customers and Administration users, with just-in-time (JIT) account provisioning and OIDC-group-to-Shopware-role/group mapping.

> **Status**: v0.1.0 + unreleased changes (see [CHANGELOG.md](CHANGELOG.md)) — early-stage. Unit-tested, plus an integration suite against a real Shopware kernel and Dex and a Playwright browser suite. Review [Upgrading](#upgrading) and [Known Limitations](#known-limitations) before relying on this in production.

## Why This Plugin?

Shopware's built-in authentication is password-based. This plugin bridges Shopware 6 to your corporate Identity Provider (IdP), so Storefront customers and Administration users can sign in with the same identity your organization already manages — with optional passwordless Passkey login as a fully independent alternative that needs no external IdP at all.

## Key Features

- **Dual SSO Flows**: separate Storefront (customer) and Administration (admin) OIDC login, sharing one verification pipeline
- **Multi-Provider Support**: configure multiple OIDC providers, each with its own client credentials, endpoints, and behavior
- **Auto-Discovery**: populate endpoints from an IdP's `.well-known/openid-configuration`
- **JIT Provisioning**: auto-create Storefront customers and/or Administration users on first login
- **Group/Role Mapping**: map OIDC group claims to Shopware customer groups and ACL roles, case-insensitively, first match wins, with configurable defaults
- **Claims-Based Access Control**: per-provider rules (`equals`, `contains`, `ends with`, `email domain is`, `exists`, …) on the IdP's claims that must all pass before anyone is logged in or provisioned, each with its own denial message
- **Rich Attribute Mapping**: map claims to 19 Shopware fields — identity (email, username, name, birthday, gender, phone) plus full billing/shipping address
- **Subject-Based Account Binding**: accounts are bound to the provider and the IdP's `sub`, never matched by the email claim alone; `email_verified` is required by default, and existing accounts are only linked explicitly ("Connect SSO") or with an opt-in
- **Step-Up Re-Authentication**: Shopware's "confirm your password" dialog in the Administration also accepts a fresh SSO login or a passkey
- **SSO-Only Mode**: optionally disable password login for customers and/or admins, with guards against locking everyone out and a break-glass environment variable
- **Logout in Both Directions**: RP-initiated logout with RFC 7009 token revocation, plus OIDC Back-Channel and Front-Channel Logout
- **PKCE + Nonce**: always-on PKCE (S256 or plain, configurable), single-use state/nonce for every authorization request, and a browser-binding cookie against login CSRF
- **JWT Verification**: RS256/384/512, PS256/384/512 and ES256/384/512 signature verification with JWKS caching and key selection by `kid`
- **Base64-Encoded Claims**: decode exactly the claims you list (e.g. ZITADEL metadata); nested role objects are supported
- **Health Checks & Alerting**: a `/sw6oidc/health` endpoint for uptime monitors (optionally token-protected) with setup warnings, on-demand diagnostics per provider, and a scheduled reachability check that posts a webhook alert (Slack/Teams/…) once per outage
- **Session Activity Log**: every OIDC/Passkey login with IP, user agent, logout time and reason in *Settings > Plugins > OIDC & Passkey sessions*, with a "Force logout" action
- **Passkey (WebAuthn/FIDO2) Login**: independent passwordless sign-in for both Administration and Storefront with required user verification, self-service registration and login, bridged into native authentication the same way OIDC is
- **Public Client Support**: PKCE-only flows without a client secret (RFC 6749 §2.1)
- **Encrypted Secrets, Masked Logs**: client secrets and security state encrypted at rest; a dedicated log channel at level `warning` by default, with a debug toggle in the plugin settings

---

## Requirements

- **PHP**: 8.2 – 8.5
- **Shopware**: `>=6.7.15.0 <6.8.0.0`
- **Identity Provider**: any OIDC-compliant IdP (Authelia, Keycloak, Auth0, Okta, Azure AD, Google Workspace, Zitadel, etc.)
- **HTTPS**: required in production — WebAuthn requires a secure context, and IdP redirects should always use HTTPS
- **Reverse proxy / CDN**: `framework.trusted_proxies` **must** be configured, so Shopware sees the real client IP (rate limiting is per client IP — see [Rate limiting](#rate-limiting))
- **Optional**: Redis (`SW6OIDC_REDIS_DSN`) for one-time tokens; not required, also not on several app servers. If used, it must not evict keys (`maxmemory-policy noeviction`).

Composer dependencies (installed automatically): `web-token/jwt-library` (`^4.0`) and `web-auth/webauthn-lib` (`^5.3`). Everything else (OAuth server, PSR-7 bridge) comes with Shopware itself. The plugin is distributed through Composer only.

---

## Installation

```bash
composer require martinkuhl/shopware6-oidc-sso
bin/console plugin:refresh
bin/console plugin:install --activate Sw6Oidc
bin/console cache:clear
```

No JavaScript build is needed: the built Administration bundle (`src/Resources/public/administration`) and Storefront bundle (`src/Resources/app/storefront/dist`) ship with the plugin. `plugin:install` copies the Administration assets to `public/bundles`, and activating the plugin recompiles the theme, which picks up the Storefront bundle (unless `SHOPWARE_SKIP_THEME_COMPILE` is set; then run `bin/console theme:compile`).

Only when you change the plugin's JavaScript or templates do you need to rebuild — and commit the result:

```bash
SHOPWARE_ADMIN_BUILD_ONLY_EXTENSIONS=1 ./bin/build-administration.sh   # plugins only; core ships prebuilt
./bin/build-storefront.sh
```

The plugin's database schema is created by a migration, not an install hook — it runs automatically as part of `plugin:install`. If you ever need to run it explicitly (or re-run after a manual reset):

```bash
bin/console database:migrate Sw6Oidc --all
```

### Register URLs with Your Identity Provider

| URL | IdP field | Required | Notes |
|-----|-----------|----------|-------|
| `https://your-shop.com/sw6oidc/callback` | Redirect URI (Storefront) | **Yes**, for customer SSO | Authorization code callback for Storefront login |
| `https://your-shop.com/api/sw6oidc/admin/callback` | Redirect URI (Admin) | **Yes**, for admin SSO | Authorization code callback for Administration login, "Connect SSO" on the admin profile and SSO step-up |
| `https://your-shop.com/api/sw6oidc/provider/test-callback` | Redirect URI | Optional | Only needed if you use the **Run live login test** button on a provider's detail page in the Administration — the IdP redirects back here with the same strict exact-match check as the other two URIs |
| `https://your-shop.com/sw6oidc/backchannel-logout` | Back-Channel Logout URI | Optional | Lets the IdP end shop sessions when the user logs out at the IdP (see [Back-Channel Logout](#back-channel-logout)). Enable "session required" / `backchannel_logout_session_required` if the IdP offers it. Logout tokens must contain `jti` and a current `iat` |
| `https://your-shop.com/sw6oidc/frontchannel-logout` | Front-Channel Logout URI | Optional | Alternative to Back-Channel Logout for IdPs that only support the browser-based variant; enable "session required" (`frontchannel_logout_session_required`) — the plugin needs `iss` and `sid` |
| Your shop's account login page and `https://your-shop.com/admin/` — **or** only `https://your-shop.com/sw6oidc/postlogout` | Post Logout Redirect URI | Optional | Where the IdP returns the user after RP-initiated logout. By default customers return to `/account/login` and admins to the Administration. If the IdP accepts only one URI, set the provider's **Post-logout redirect URI** to `https://your-shop.com/sw6oidc/postlogout` and register just that: it sends customers and admins to the right login page |

Register only the redirect URI(s) for the flow(s) you intend to use — you don't need both if, say, only customer SSO is enabled for a given provider.

> Prefer Back-Channel Logout where the IdP supports it: it does not depend on the user's browser still being open on the IdP's logout page.

---

## Configuration Guide

Unlike a typical Shopware plugin, providers are **not** configured in `Settings > System > Plugins` config fields — each provider is a database-backed entity managed through a dedicated Administration module.

### Configuring a Provider

1. Navigate to the **OIDC & Passkey SSO** section in the Administration (the plugin's own provider management module).
2. Add a new provider and fill in:
   - **App Name**: an identifier for this IdP (e.g. `keycloak`, `authelia`)
   - **Display Name**, **Sort Order**: SSO button label/ordering when multiple providers are configured
   - **Client ID** / **Client Secret**: from your IdP (see [Security Considerations](#security-considerations) regarding secret storage). Changing an endpoint URL of an existing provider requires entering the client secret again in the same save.
   - **Public Client**: enable for PKCE-only flows with no client secret
   - **Well-Known Config URL** *(optional)*: your IdP's discovery document — populates the endpoint fields below automatically
   - **Authorize / Token / User Info / End Session / Revocation / JWKS Endpoints**, **Issuer**: filled by discovery, or entered manually
   - **Scope** (default: `openid profile email`): keep `openid` in it. With `openid` the IdP must return an `id_token`, otherwise the login fails; identity claims (`sub`, `email`, `email_verified`) are taken from the signed `id_token`
   - **PKCE Method**: `S256` (default) or `plain`
   - **Base64-encoded claims**: only for IdPs that Base64-encode some claim values (e.g. ZITADEL metadata) — list exactly those claim names; a name also covers everything nested under it, `*` decodes all claims (not recommended). Other claims are never decoded
   - **Group Attribute**: the claim key holding group memberships (default: `groups`)
   - **Login Type**: `customer`, `admin`, or `both`
   - **Auto Create Customer** / **Auto Create Admin**: enable JIT provisioning per user type
   - **Show Customer Link** / **Show Admin Link**: whether the SSO button appears on the respective login page
   - **Require a verified email** *(Account linking card, default on)*: refuse logins unless the IdP sends `email_verified: true` for the standard `email` claim. Turn off only for IdPs that never send the claim and fully control every user's email address. An email mapped from a custom claim never counts as verified
   - **Link existing accounts by verified email** *(Account linking card, default off)*: on a first SSO login, connect an existing Shopware account with the same, verified email. Off: existing accounts must be connected explicitly with **Connect SSO** (see [Account binding](#account-binding)). Superadmins are never linked automatically
   - **Disable non-OIDC Customer Login** / **Disable non-OIDC Admin Login**: turn off native *password* login for that user type shop-wide (see [SSO-only mode](#sso-only-mode)). Emergency override: set `SW6OIDC_ALLOW_PASSWORD_LOGIN=1`.
   - **Front-channel logout ends admin sessions** *(default off)*: see [Front-Channel Logout](#front-channel-logout)
   - **Is Active**: whether this provider is usable at all
   - **Default Customer Group** / **Default ACL Role** *(Account creation card)*: fallback assignment when no group mapping matches
   - **HTTP Timeout**, **JWKS Cache TTL**: per-provider tuning (defaults: 30s, 86400s; allowed 1–60s and 60–86400s)
3. Save.

Deleting a provider that still has connected accounts asks for confirmation first: those users lose their SSO binding and must connect again (with **Connect SSO**) after a new provider is set up. Through the plain Admin API such a provider can't be deleted.

Use **Run live login test** on the saved provider: it runs a real login in a popup (nobody is logged in), shows which claims the IdP sent — check that `email_verified` is `true` — and previews the access-control result. It requires the provider *editor* permission.

### Account binding

An SSO account is bound to the provider **and the IdP's subject** (`sub`). The email claim alone is never enough to log into an existing account:

| Situation on the first SSO login | Result |
|---|---|
| No Shopware account with this email | Created if **Auto Create** is on, else refused |
| An account with this email exists, not yet connected | Refused with "connect SSO in your profile" — unless **Link existing accounts by verified email** is on, the email is verified and the account is not a superadmin |
| The account is connected to another provider, or to another subject of this provider | Refused |
| `email_verified` is not `true` and **Require a verified email** is on | Refused |

**Connect SSO**: the owner of an existing account logs in as usual (password or passkey) and connects it:

- **Storefront customers**: *My Account > Profile*, one button per provider.
- **Administration users**: *My profile*, after confirming their identity (password, passkey or SSO). This is the only way to connect a superadmin.

Bindings created before this version are upgraded with the subject on the next login, but only when the IdP sends a verified email.

### SSO-only mode

**Disable non-OIDC Customer Login** / **Disable non-OIDC Admin Login** turn off password login for that user type. OIDC and passkey logins keep working.

- **Administration**: every username/password token request is refused, however it is encoded. `client_credentials` with *user* access keys is refused too (integration keys are unaffected); `SW6OIDC_ALLOW_USER_ACCESS_KEYS=1` allows them again.
- **Storefront / Store API**: password login, registration and double-opt-in confirmation are refused; guest checkout stays possible. The login and registration forms are hidden.

Guards against locking everyone out:

- The flag can only be switched on once at least one account of that type is connected to this provider, and only while an SSO button is still shown on that login page.
- For admins: if other active admins have no SSO connection, saving asks for an explicit confirmation.
- While the flag is on, the last admin able to log in via SSO — or the last provider they use — can't be deleted or deactivated.
- Switching the flag on ends existing sessions of accounts without an SSO connection.
- Emergency override: `SW6OIDC_ALLOW_PASSWORD_LOGIN=1`.

The flag is shop-wide: providers are not scoped to sales channels.

### Attribute Mapping

Per provider, map OIDC claims to Shopware fields. Identity fields have OIDC-standard defaults and work out of the box if your IdP uses standard claim names; address fields have **no default** and must be mapped explicitly if you want them populated.

| Type | Default claim | Notes |
|---|---|---|
| Email | `email` | Required — login fails if this resolves to nothing valid |
| Username | `preferred_username` | |
| First name | `given_name` | |
| Last name | `family_name` | |
| Birthday | `birthdate` | Only `YYYY-MM-DD` between 1900 and today; other values are skipped |
| Gender | `gender` | Recognizes English and German values (`male`/`female`, `mann`/`männlich`/`frau`/`weiblich`, etc.) → Shopware salutation |
| Phone | `phone_number` | |
| Billing/Shipping address (city, state, country, street, phone, zip) | *(none)* | Configure per field if you want auto-populated addresses |

Each mapping can optionally **transform** the claim value before it is stored (applied on every login):

| Transform | Parameters | Example |
|---|---|---|
| Concatenate claims | claims to append, separator (default space) | street `Main St` + `house_no` → `Main St 5` |
| Split | separator, part index (`-1` = last) | `name` split on space, index `-1` → last name |
| Prefix | text | `42` → `OIDC-42` |
| Regex replace | PCRE pattern, replacement | `/\D+/` → `` strips non-digits from a phone number |

An invalid regex pattern is rejected when the mapping is saved. A transform that fails at login uses the untransformed value and logs a warning — except on **Email** and **Username**, where a failed transform fails the login.

### Group / Role Mapping

Per provider, map OIDC group names to Shopware ACL roles (admin) or customer groups (Storefront):

1. Add a mapping: **OIDC Group** → **ACL Role** (or **Customer Group**), with a **Sort Order**.
2. Matching is case-insensitive; the first matching mapping (by sort order) wins.
3. If nothing matches, the provider's configured **Default ACL Role** / **Default Customer Group** applies.
4. For admin users, JIT creation is refused outright if no role can be resolved at all (no match and no default) — the plugin will not create an admin without an ACL role.

#### Granting full superadmin via an OIDC group

A Shopware **superadmin** (`admin = true` on the user) bypasses ACL entirely — it is a different mechanism from ACL roles, and no ACL role, however permissive, is fully equivalent to it. Because of that, an `admin_role` mapping (or the Default ACL Role) can never make an OIDC-provisioned admin a true superadmin.

If you specifically need that, it requires **two deliberate, independent steps** on the provider — this is intentionally not a side effect of any other setting, since granting full superadmin from IdP group membership is security-sensitive:

1. Enable **Allow "Grant superadmin" group mappings** (Superadmin grant card).
2. Add a Group/Role Mapping row with mapping type **Grant superadmin**, with the OIDC group that should receive it.

Only when *both* are true does a group match result in `admin = true`. Only grant this for a narrow, tightly controlled IdP group — everyone in it gets unrestricted access to the entire shop.

By default superadmin is never revoked automatically by a later login whose groups no longer match (to avoid a transient IdP claims issue silently locking out your only superadmin) — revoke it manually in the Administration. With **Sync admin role** on, you can additionally enable **Role sync may revoke superadmin**: the superadmin flag is then removed when a login's groups no longer grant it (the mapped ACL role remains). It is never removed from the last active superadmin.

### Claims-based access control

The **Access control** card on a provider lets you restrict who may log in at all, based on the claims the IdP returns — for example "only members of the `staff` group" or "only verified email addresses". Rules are checked after the id_token/userinfo claims are verified and **before** any account is looked up, created or synced, so a denied login never provisions anything.

| Operator | Passes when |
|---|---|
| equals | Any value of the claim equals the rule value (for a list claim: any entry). |
| does not equal | The claim is present and none of its values equals the rule value. A **missing claim denies**. |
| contains | For a list claim (e.g. `groups`): an entry equals the value. For a text claim: one of its whitespace- or comma-separated words equals the value exactly — never a substring match. |
| does not contain | The claim is present and "contains" is false. A **missing claim denies**. |
| ends with | Any value ends with the rule value. |
| email domain is | Any value is a valid email address whose domain is exactly the rule value (a leading `@` is ignored). Use this, not "ends with", to restrict by email domain. |
| exists / does not exist | The claim is present (absent). No value needed. |

- **All rules must pass** (AND), checked in sort order. The first failing rule denies the login and shows its **message** to the user (Storefront flash message, Administration login screen); without a message a generic "access denied" text is shown. Messages are plain text.
- **Claim keys** use the flattened dot notation, e.g. `realm_access.roles` for Keycloak realm roles. List claims are matched by entry (`groups`, not `groups.0`); for Zitadel-style role objects (`{"Admins": {...}}`) the role names are the entries.
- The negative operators deny when the claim is missing, so a claim the IdP omits (group overage, ungranted scope) can never skip a deny rule.
- Comparisons ignore case and surrounding whitespace; `true`/`1` and `false`/`0` are treated as equal. An unknown operator denies (fails closed).
- **Upgrading**: "equals", "does not equal", "contains" and "does not contain" are stricter than before (see [Upgrading](#upgrading)) — check existing rules with the live login test.
- No rules = everyone who authenticates at the IdP may log in (the previous behavior).
- Rules are included in `sw6oidc:config:export`/`import`.

### Sync on every login

By default, a mapped claim is only ever applied once, at account creation — logging in again afterwards just authenticates the existing account, untouched. The **Sync on every login** card adds five independent, opt-in toggles that instead re-apply the current claims/mapping on every single login, for an account already bound to this provider:

| Toggle | Re-applies on every login |
|---|---|
| Sync customer profile | First name, last name, date of birth, salutation (Storefront) |
| Sync customer address | The existing default billing address (Storefront) — no effect unless a billing address is mapped |
| Sync customer group | The Group/Role Mapping's resolved customer group (Storefront) |
| Sync admin profile | First name, last name (Administration) |
| Sync admin role | The Group/Role Mapping's resolved ACL role, or superadmin grant (Administration). The resolved role **replaces** the user's ACL roles, so a role removed at the IdP is removed in the shop |

Each is a partial update: a claim that isn't mapped, or a group/role mapping that doesn't resolve to anything, is simply left as-is rather than being cleared or reset to a placeholder (admin role sync leaves the roles untouched when nothing resolves). Address sync only ever updates a customer's *existing* address in place — it never creates one. Superadmin is only revoked with the separate opt-in described above.

### Passkey Settings

Passkeys are configured independently of OIDC — no external IdP involved. Found under the plugin's system config:

- **Enable Passkey Login for Administration users**
- **Enable Passkey Login for Storefront customers** (configurable per sales channel)
- **Relying Party Name**: shown in the browser/OS passkey prompt (defaults to the shop name)
- **Relying Party ID (domain) override**: the domain a passkey is bound to (a custom field that shows your current hostname as a placeholder). If left blank: the host of `APP_URL` for the Administration, and the current sales channel domain's host for the Storefront. The request's `Host` header is never used.

**Multi-domain caveat**: a passkey is bound to a single Relying Party ID. If you change this setting, `APP_URL` or the sales channel domains, previously registered passkeys can stop validating and users must re-register. Allowed origins are checked exactly (no subdomains): a domain that isn't the RP ID or below it can't be used for passkeys.

Passkeys require **user verification** (PIN or biometrics) for registration and login. Every passkey endpoint answers 404 while passkeys are disabled for that user type.

**Requirements**: HTTPS (WebAuthn requires a secure context; `localhost` is exempt for local development) and a browser with WebAuthn support.

---

### Health checks & alerting

- **`GET /sw6oidc/health`** (for uptime monitors): without `SW6OIDC_HEALTH_TOKEN` it answers only `{"status"}`. With the token set (and sent), it also returns `"activeProviders", "incompleteProviders", "unreachableProviders", "unknownProviders", "infrastructure": {"warnings": [...]}`. It never contacts an IdP itself and exposes only counts and warning codes, no provider names or URLs. The result is cached for 30 seconds.

  | `status` | HTTP | Meaning |
  |---|---|---|
  | `ok` | 200 | Every active provider is usable |
  | `degraded` | 200 | Some provider is incomplete (missing configuration, undecryptable client secret) or failed its last monitored check, but SSO still works through another one |
  | `down` | 503 | No active provider is usable |
  | `unconfigured` | 200 | No active provider |

  Only providers with alerting configured (threshold > 0 and a webhook) count their last scheduled check; a result older than 15 minutes counts as `unknown`, not as a failure. Set `SW6OIDC_HEALTH_TOKEN` to protect the endpoint and see the details: requests must then send the value in the `X-Sw6oidc-Health-Token` header, otherwise they get HTTP 401.
- **Infrastructure warnings** (in the health response and in **Run diagnostics**): `redis_dsn_unusable` — `SW6OIDC_REDIS_DSN` is set, but Redis can't be used (PHP extension missing, unreachable, authentication failing; see the log); `multi_node_without_redis` — several app servers handled SSO in the last 15 minutes and Redis isn't in use; `redis_may_evict` — the Redis used for one-time tokens may evict keys (its `maxmemory-policy` isn't `noeviction`), so a login can fail or a logout token can be replayed. Logins stay correct in both cases (one-time tokens are in the database), but on several servers the rate limiter and JWKS cache are per server unless Shopware's cache pools are shared. Warnings never change the status.
- **Run diagnostics** (provider detail page, *Health checks & alerting* card): configuration problems, the one-time token store in use (Redis or database), a live reachability probe (the JWKS must contain keys; without a JWKS endpoint the discovery document must have an `issuer`), the alerting state and infrastructure warnings.
- **Alerting**: set **Alert after consecutive failed checks** (0 = off) and an **Alert webhook URL**. A scheduled task (every 5 minutes) probes each such provider; once the threshold is reached, **one** JSON message is POSTed per outage (with a `text` field for Slack, Mattermost, Teams workflows and similar), optionally followed by a recovery message. An alert that can't be delivered is retried on the next run. Changing the provider during an outage does not trigger a second alert.
- The webhook URL is stored encrypted, never shown again after saving, SSRF-checked on save and before every call, and not included in `sw6oidc:config:export` (enter it again after an import). The scheduled task needs Shopware's scheduled-task runner / message queue worker to be running.

### Session activity log

*Settings > Plugins > OIDC & Passkey sessions* lists every login made through OIDC or a passkey (Storefront and Administration): when, which account, which method and provider, the client IP address and user agent, and when and why the session ended (logout, IdP back-/front-channel logout, forced).

- **Force logout** (requires the *force logout* permission of this module): ends a customer's OIDC session exactly. For passkey logins and for Administration users it ends **all** sessions of that account — Shopware can't end a single one of those.
- The log is read-only through the Admin API (entries can't be edited or deleted there).
- Entries are deleted by a daily scheduled task after `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` days (default 90, `0` keeps them forever). IP addresses and user agents are personal data — choose the retention to match your privacy policy, and set `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP=1` to store IP addresses truncated (IPv4 /24, IPv6 /64).
- Deleting a user or customer removes its SSO connection, passkeys, session data and activity entries; deactivating one ends all of its sessions.
- Logins made with the password form are not recorded; neither are sessions that ended by simply expiring.

## Usage Examples

### Customer Login Flow

1. Customer clicks the SSO button on the Storefront login page (`/sw6oidc/login`).
2. Shopware redirects to the IdP's authorization endpoint with PKCE and a single-use state/nonce.
3. Customer authenticates at the IdP.
4. IdP redirects back to `/sw6oidc/callback` with an authorization code.
5. Shopware exchanges the code for tokens, verifies the ID token's JWT signature and claims, fetches userinfo, and maps claims to a customer profile.
6. The account is resolved by provider and subject (see [Account binding](#account-binding)); if there is none and no existing account with that email, and auto-create is enabled, a new customer is created with mapped group/profile/address (Flow Builder's "customer registered" trigger fires).
7. Customer session established; the customer returns to the page they started from (same-site targets only).

### Admin Login Flow

1. Admin clicks the SSO button on the Administration login screen, hitting `/api/sw6oidc/admin/login`.
2. Same authorization/callback pipeline as the customer flow runs against `/api/sw6oidc/admin/callback`.
3. On success, the admin is redirected back into the Administration SPA at `#/login?sw6oidc_nonce=...` with a short-lived, one-time nonce.
4. The Administration frontend exchanges that nonce for a real OAuth2 access/refresh token pair via a background request, then completes login the same way a password login would.

### Passwordless Login (Passkeys)

**Customer flow**: a logged-in customer registers a passkey from **My Account > Passkeys**. Registration requires a login within the last 10 minutes; otherwise the customer is sent through a fresh login first (SSO-connected customers via their IdP). On a later visit, they click "Login with Passkey" with no email/username needed (usernameless/discoverable login) — the browser resolves the matching credential.

**Admin flow**: an already-authenticated admin registers a passkey from their own profile after confirming their identity (password, passkey or SSO). On a later visit, they click "Login with Passkey" — login is usernameless, the browser offers the admin's passkeys.

A new passkey is written to the audit log and triggers the Flow Builder event "Passkey registered" (e.g. to send the owner a notification).

### Re-confirming your identity in the Administration (step-up)

Shopware asks admins to confirm their password before sensitive changes (e.g. editing users or integrations). SSO-provisioned admins don't know their random password, so the plugin adds two buttons to that dialog:

- **Single sign-on**: a fresh login at the admin's own connected provider in a popup (`prompt=login`). The IdP must return `auth_time` in the `id_token`; IdPs that don't (e.g. Dex) can only use the passkey option.
- **Passkey**: one of the admin's own passkeys, with user verification.

The result is a short-lived (5 minutes) confirmation token, the same kind Shopware's password check produces. Connecting SSO on the own profile and registering an admin passkey require this confirmation.

---

## Security Considerations

### HTTPS is Required

Production deployments must use HTTPS for both the IdP redirect and WebAuthn ceremonies. `localhost` is exempt for local development only.

Every IdP URL the plugin fetches server-side (discovery, token, userinfo, JWKS, revocation, end-session) must be **HTTPS on a public address** — this is enforced when a provider is saved (SSRF protection: private, loopback, link-local, CGNAT and similar ranges are rejected) and again on every outbound request, including redirects (so DNS changes after saving can't be abused). For a local development IdP on plain HTTP or a private/docker network address, set `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1` — never in production.

### PKCE, State, and Nonce

Every authorization request generates a single-use state token, PKCE code verifier, and nonce, stored for 600 seconds and consumed exactly once (atomic get-and-delete) — replay of a used or expired state is rejected outright. They are stored in the database (`sw6oidc_one_time_token`, encrypted), or in Redis when `SW6OIDC_REDIS_DSN` is set and usable; both are atomic across several app servers and survive `cache:clear`. The login is also bound to the browser that started it by an HttpOnly cookie, so a callback or admin login link can't be completed in another browser (login CSRF).

### JWT Verification

ID tokens are verified for signature (RS256/384/512, PS256/384/512, ES256/384/512 — HS* and `none` are never accepted, nor tokens with a `crit` header), expiry, not-before, issued-at (required, 60 seconds clock leeway), issuer, audience, authorized party (`azp`) and nonce (required). The connection test and discovery warn when the IdP only offers algorithms the plugin doesn't support. JWKS keys are fetched and cached per provider and selected by `kid`; a failed fetch pauses further fetches for 60s (circuit breaker), and a token signed with a `kid` missing from the cached set triggers a rate-limited refetch so IdP key rotation doesn't lock users out until the cache expires.

When the scope contains `openid`, the IdP must return an `id_token`. Userinfo claims are merged in, but userinfo must describe the same `sub`, and `sub`, `email` and `email_verified` come from the `id_token` when it contains them.

### Per-User IdP Binding

An account is permanently bound to one provider and IdP subject (see [Account binding](#account-binding)). A login for the same account via a **different** provider, or a different identity at the same provider, is rejected — this prevents an account's effective security level from being the weakest of multiple IdPs. The binding is shown as **OIDC Provider** (provider name and bind date, or "none") in the Administration: as a column in *Settings > Users & permissions*, on each admin user detail page, on the logged-in admin's own profile (*My profile > General*), and in the customer detail base info next to *Last login*. If a deliberate IdP migration is needed, the **Unlink IdP** button there removes the binding (requires `users_and_permissions.editor` / `customer.editor`), so the account can be connected to a different provider. Deleting a user or customer also removes its binding.

### RP-Initiated Logout

On Storefront logout and on Administration logout (user menu → Log out), the plugin redirects to the IdP's end-session endpoint (if configured) and fire-and-forget revokes the login's IdP refresh and access tokens via RFC 7009. A failed revocation call never blocks the user from logging out locally. Store API clients receive the IdP logout URL as `redirectUrl` in the logout response. An admin's logout only ends that browser's session, not the admin's sessions on other devices. After the IdP logout, customers land on `/account/login` and admins on the Administration login page — unless the provider's **Post-logout redirect URI** is set, which replaces both (use `https://your-shop.com/sw6oidc/postlogout` to keep the per-flow login pages with a single registered URI; its `state` parameter is signed, so a crafted link can't choose the destination). Inactivity/session-timeout logouts in the Administration stay local: the re-login dialog offers the SSO provider(s) and Passkey (plus the password, unless password login is disabled), and returns the admin to the page they were on.

**Authelia note**: Authelia does not implement standards-based RP-Initiated Logout / OIDC Session Management — its discovery document has no `end_session_endpoint` at all, so **auto-discovery leaves this field blank** and it must be set manually to Authelia's own portal logout page:
```
https://auth.your-domain.example/logout
```
(the bare portal path, not anything under `/api/oidc/...`). The plugin auto-detects this shape — any End-Session Endpoint whose path ends in `/logout` and contains neither `/oauth2/` nor `/oidc/` is treated as Authelia-style forward-auth logout, and the plugin sends `?rd=<url>` instead of the standard `id_token_hint`/`state`/`post_logout_redirect_uri` params. No Post Logout Redirect URI needs registering with Authelia for this.

### Back-Channel Logout

With [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html), the IdP notifies the shop server-to-server when a user's IdP session ends (logout at the IdP or in another application, session revoked by an administrator). Register `https://your-shop.com/sw6oidc/backchannel-logout` as the client's Back-Channel Logout URI.

- The logout token is verified like an id_token (signature against the provider's JWKS, `iss`, `aud`, `exp`) plus the logout-specific rules: a back-channel logout `events` claim, `sub` and/or `sid`, **no** `nonce`, a **`jti`** (required; replayed tokens with the same `jti` are ignored) and an **`iat`** no older than 5 minutes (plus 60 seconds clock leeway). Keep the IdP's and the shop's clocks in sync.
- With a `sid`, only the shop sessions created from that IdP session end; with only a `sub`, all of that user's shop sessions from this provider end. This needs the IdP to put `sid` into the id_token (usually enabled together with "backchannel logout session required").
- **Customers** are logged out of exactly that session. **Administration users** are logged out of *all* their Administration sessions: Shopware's admin access tokens can't be revoked one by one, so the plugin revokes the user's refresh tokens and invalidates every access token issued so far (the mechanism Shopware uses after a password change — the password itself is not changed).
- Only OIDC logins recorded in the plugin's session table are known; sessions from before the upgrade to this version and passkey logins are not affected.
- Invalid requests are answered with HTTP 400 (always the same `invalid_request` body); an address sending more than 10 invalid tokens per minute for a provider gets HTTP 429 for the rest of the minute. Correctly signed logout tokens are never rate-limited.

### Front-Channel Logout

With [OIDC Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html), the IdP's logout page loads `https://your-shop.com/sw6oidc/frontchannel-logout?iss=…&sid=…` in a hidden iframe. The plugin ends every customer session created from that IdP session and always answers with a 1×1 transparent GIF, whatever the outcome.

- `iss` and `sid` are required ("session required" at the IdP, and `sid` in the id_token). Without them nothing happens: the shop's own cookies are not sent inside a cross-site iframe, so the browser alone can't identify the session.
- The request is unauthenticated by design of the protocol — anyone who knows a `sid` can end that session. For that reason **Administration sessions are left alone by default** (they can only be ended all at once); enable **Front-channel logout ends admin sessions** on the provider only if your IdP supports nothing but front-channel logout. Back-Channel Logout (signed) always ends admin sessions.
- Malformed requests count as failed requests for rate limiting.

### Rate limiting

The plugin's unauthenticated endpoints are rate-limited **per client IP address** (IPv6 per /64), separately per endpoint:

- Endpoints that create state on every request (starting an SSO login, passkey login options): 30 requests per minute.
- Endpoints that redeem something (callbacks with a valid state, the admin nonce exchange, passkey login, error messages, step-up, Back-/Front-Channel Logout): 10 **failed** requests per minute. Successful logins and valid logout notifications never count, so an office behind one NAT address or a busy IdP is not throttled. Callbacks with an unknown or expired state don't count either.

**Behind a reverse proxy, load balancer or CDN, `framework.trusted_proxies` must be configured** (and `trusted_headers`), otherwise Shopware sees the proxy's address for every visitor and all of them share one budget — a few failed attempts can then block SSO for everyone. The counters live in Shopware's `cache.rate_limiter` pool (falls back to the app cache).

### Passkey (WebAuthn) Security

- Public-key cryptography only — the server stores a public key and signature counter, never a shared secret; credentials are phishing-resistant (bound to the origin).
- Registration requires a discoverable/resident credential, enabling usernameless login.
- User verification (PIN or biometrics) is required for registration and login.
- A registration only completes for the account that started it, and a signature counter going backwards (a possible cloned authenticator) disables the credential.
- An account can have at most 20 passkeys. The Storefront passkey endpoints refuse cross-site requests.
- Attestation conveyance is `none` — the plugin only verifies the public key, not the authenticator's hardware provenance. This favors broad device compatibility over attestation-based trust.
- Passkeys are bound to a single Relying Party ID (domain) — see [Passkey Settings](#passkey-settings).
- Deleting a user or customer deletes their passkeys.

### Client Secret Storage — Read This

Client secrets and alert webhook URLs are **encrypted at rest** and are **write-only** in the Administration: after saving, the secret is never shown or returned by the Admin API again — leave the field empty to keep the stored value, or type a new one to replace it. The current envelope format (`sw6oidc_v2:`) uses XChaCha20-Poly1305 with a separate key per field, derived from Shopware's `APP_SECRET`. Existing plaintext secrets and older `sw6oidc_v1:` envelopes are re-encrypted by the plugin's migrations on `plugin:update`. The same encryption protects the plugin's stored session data and one-time tokens, in the database and in Redis.

**Keep `APP_SECRET` stable.** Rotating it makes every stored client secret undecryptable; OIDC logins for those providers then fail with a "re-enter the client secret" error (and the health endpoint reports the provider as incomplete) until an admin saves each provider with its secret again. A database dump alone no longer exposes the secrets, but a dump *plus* the `APP_SECRET` does.

---

## Known Limitations

- **IdP-initiated logout and force logout end all Administration sessions of the user** — not just the one created from the IdP session (Shopware admin access tokens cannot be revoked individually).
- **"Sync on SSO" is per provider, not per attribute** — all five provider-level toggles (customer profile/address/group, admin profile/role) are applied on repeat logins, but there is no per-attribute sync control.
- **"Disable password login" is shop-wide** — providers are not scoped to sales channels.
- **OIDC step-up needs `auth_time`** — IdPs that don't return it in the `id_token` (e.g. Dex) can only confirm admin identity with a passkey or password.
- **Several app servers without Redis** — logins stay correct (one-time tokens are in the database), but the rate limiter and the JWKS cache are per server unless Shopware's cache pools (`cache.rate_limiter`, `cache.app`) are shared. The health endpoint warns with `multi_node_without_redis`; set `SW6OIDC_REDIS_DSN` (e.g. `redis://:password@redis:6379/2`, or `rediss://` for TLS) or share the cache pools.
- **Logs can contain personal data** — the plugin log (`var/log/sw6oidc-<env>.log`) masks credentials, but with **Enable debug logging** on it contains claim keys and more personal data. Switch the toggle off after troubleshooting.

---

## Upgrading

The unreleased version changes security-relevant behavior. Check these points before updating a running shop (details in [CHANGELOG.md](CHANGELOG.md)):

1. **Run the migrations** (`bin/console plugin:update Sw6Oidc`). They add the identity-binding columns, the session/one-time-token tables, re-encrypt stored secrets to the v2 envelope (needs the same `APP_SECRET`), and convert `claim_encoding = base64` to `base64_claims = ["*"]`. `bin/console database:migrate-destructive Sw6Oidc --all` drops the unused button label/color columns and the old `claim_encoding` column. Update the package first: `composer update martinkuhl/shopware6-oidc-sso` (the dependencies changed).
2. **`email_verified` is required.** Every provider now has **Require a verified email** on. Make sure the IdP sends `email_verified: true` (check with the live login test), or switch the setting off deliberately for an IdP that fully controls its users' email addresses.
3. **Existing accounts are no longer linked by email.** A first SSO login for an email that already has a Shopware account is refused. Either let users connect their account with **Connect SSO** (customer: *My Account > Profile*; admin: *My profile*), or enable **Link existing accounts by verified email** on the provider. Superadmins can only be connected with Connect SSO. Accounts already bound to a provider keep working; their binding is upgraded with the IdP subject on the next login with a verified email.
4. **The `openid` scope requires an `id_token`.** A token response without one now fails the login.
5. **Passkeys require user verification.** Authenticators without PIN/biometrics can no longer register or log in. The RP ID now defaults to the host of `APP_URL` (Administration) or the sales channel domain (Storefront) instead of the request host — check that registered passkeys still work if these differ.
6. **Password confirmation in the Administration** is now done with Shopware's own dialog plus the SSO/passkey buttons (step-up). The former automatic "verified" session for SSO admins is gone.
7. **Access-control rules are stricter.** "does not equal" and "does not contain" now deny when the claim is missing; "contains" on a text claim matches whole words only, never substrings (use "email domain is" or "ends with" for domains); "equals" on a list claim matches any entry. Review existing rules with the live login test.
8. **Admin role sync replaces ACL roles** instead of only adding the mapped one.
9. **State moved from the cache to the database.** Redis (`SW6OIDC_REDIS_DSN`) is now optional, also with several app servers. IdP-initiated logout only finds sessions created after the update.
10. **Logging defaults to `warning`.** Use **Enable debug logging** in the plugin settings for troubleshooting instead of `SW6OIDC_LOG_LEVEL=debug`.
11. **Front-channel logout no longer ends admin sessions** unless **Front-channel logout ends admin sessions** is enabled on the provider.
12. **Back-channel logout tokens need `jti` and a recent `iat`.**
13. **The health endpoint** answers 200 for `degraded` and 503 only for `down`; adjust monitors that relied on 503 for `degraded`. Without `SW6OIDC_HEALTH_TOKEN` it now returns only the status; set the token to get the counts and warnings.
14. **Behind a proxy/CDN, configure `framework.trusted_proxies`** — rate limiting is per client IP.
15. **Admin password login is blocked at the credential check** in SSO-only mode, including `client_credentials` with user access keys (`SW6OIDC_ALLOW_USER_ACCESS_KEYS=1` re-allows those). Customer registration is blocked in SSO-only mode as well.
16. **Session activity permissions**: force logout needs the new *force logout* permission of the sessions module; provider, passkey and session privileges can now be granted to normal roles. Force-logging-out an admin needs a superadmin.
17. **Inactive accounts can't log in through SSO.** An inactive admin is refused before any sync; a customer who can't log in (inactive, guest, other sales channel) sees "account unavailable" instead of an error page.
18. **Plugin-internal changes for extensions:** the plugin's exceptions extend `Sw6OidcException` (Shopware `HttpException`, stable `SW6OIDC_*` codes), its logger service is `sw6oidc.logger`, and `OidcCustomerLoginRoute` is gone (customer logins use Shopware's `AccountService::loginById()`).

---

## Troubleshooting

### "Callback URL mismatch" or similar error from the IdP

Verify the redirect URI registered at the IdP exactly matches:
- Storefront: `https://your-shop.com/sw6oidc/callback`
- Admin: `https://your-shop.com/api/sw6oidc/admin/callback`
- Live login test (only if you use that button): `https://your-shop.com/api/sw6oidc/provider/test-callback`

Check protocol (HTTPS required in production) and trailing slashes. Most IdPs (Authelia, Keycloak, etc.) require an *exact* string match against every registered `redirect_uri` — if you see an error like Authelia's "The 'redirect_uris' registered with OAuth 2.0 Client ... did not match 'redirect_uri' value ...", add the missing URI to the client's registered list rather than trying to make the plugin send a different one.

### Token exchange fails with HTTP 401 (`invalid_client` or similar)

For a **confidential client** (i.e. `Public client` is *off* on the provider), the plugin authenticates to the token endpoint via **HTTP Basic auth** (`client_id`/`client_secret` in the `Authorization` header), matching the `client_secret_basic` default most IdPs — including Authelia — use unless configured otherwise. If your IdP's client is instead configured for `client_secret_post` (credentials expected in the POST body) and doesn't also accept Basic auth, the token endpoint will reject the request with a 401.

For Authelia specifically, this "just works" as long as the client either omits `token_endpoint_auth_method` (defaults to `client_secret_basic`) or sets it explicitly:
```yaml
token_endpoint_auth_method: 'client_secret_basic'
```
Also double-check the `client_secret` value entered in the Shopware provider matches exactly (no trailing whitespace, and note Authelia typically expects the **hashed** secret in its own config while the *plaintext* value is what you enter in Shopware).

### What endpoint value should I use for a given field?

Rather than guessing at an IdP's exact endpoint paths (they vary by product and version), click **Load configuration** after entering the **Well-known configuration URL** (`https://your-idp.example/.well-known/openid-configuration`) — it fetches and fills in the endpoint fields directly from what the IdP itself publishes. You can also open that well-known URL in a browser to inspect the raw JSON if you want to verify a specific value.

**Exception: End-Session (Logout) Endpoint on Authelia.** Authelia's discovery document doesn't include an `end_session_endpoint` at all (it has no standards-based RP-Initiated Logout), so this one field always stays blank after "Load configuration" for an Authelia provider and must be set manually — see the Authelia note under [RP-Initiated Logout](#rp-initiated-logout).

### Login succeeds but profile fields are empty

The OIDC claim names from your IdP likely don't match your attribute mapping. Run the **live login test** on the provider to see which claims the IdP sends, or switch on **Enable debug logging** in the plugin settings and check `var/log/sw6oidc-<env>.log`, then adjust the attribute mapping to match (claim names are case-sensitive).

### "Your identity provider has not verified your email address"

The provider has **Require a verified email** on, and the IdP didn't send `email_verified: true` for the `email` claim (or the email is mapped from a different claim). Mark the email as verified at the IdP or enable the claim there; switch the setting off only if the IdP fully controls its users' email addresses.

### "An account with this email address already exists"

An unconnected Shopware account has the same email. The user logs in with their password (or passkey) and connects SSO: customers under *My Account > Profile*, admins under *My profile*. Alternatively enable **Link existing accounts by verified email** on the provider (never applies to superadmins).

### "This account is connected to a different single sign-on identity" (or similar rejection)

Per-user IdP binding is enforced — the account is already bound to a different provider, or to a different user at the same provider. The bound provider is shown as **OIDC Provider** on the admin user / customer detail page in the Administration. If a deliberate migration to a new IdP is intended, click **Unlink IdP** there and connect the account again.

### Login fails right after the IdP redirect

With `openid` in the scope the IdP must return an `id_token`. Check the IdP client's response/grant types. Clock differences of more than 60 seconds between IdP and shop also make the token invalid.

### SSO is blocked for everyone after a few failed attempts

The shop is behind a proxy or CDN without `framework.trusted_proxies`, so all visitors share the proxy's IP and rate-limit budget. Configure trusted proxies.

### SSO confirmation in the Administration's password dialog fails or is not offered

SSO step-up needs the admin to be connected to an active provider, and the IdP must return `auth_time` in the `id_token` after a fresh login. Without it, use the passkey button or the password.

### Admin JIT creation fails with "no suitable role"

Admin JIT creation requires a resolvable ACL role — either a matching group mapping or a configured default. Verify the **Group Attribute** name matches what your IdP actually sends, and that at least one role mapping (or a **Default ACL Role**) is configured for the provider. The **Default ACL Role** / **Default Customer Group** selects live in the provider's **Account creation** card — the simplest fix is usually to set a Default ACL Role there, so a role is always resolved even without any group match.

If `autoCreateAdmin` is on but neither a Default ACL Role nor an `admin_role`/`superadmin` mapping is configured, the provider detail page shows a warning banner in the Provisioning card so this can be caught before anyone actually tries to log in. When the denial does happen at login time, the admin login screen shows a specific message (rather than a generic "SSO login failed") and `sw6oidc.log` includes the denial `reason`, the `providerId`, and the `groups` the IdP actually sent — useful for spotting a group-attribute/claim-name mismatch.

Note that an ACL role, however permissive, is never a full substitute for Shopware's native superadmin — see [Granting full superadmin via an OIDC group](#granting-full-superadmin-via-an-oidc-group) if that's actually what you need.

### "Login with Passkey" doesn't appear

Confirm the corresponding toggle (admin/customer) is enabled, the site is served over HTTPS (or `localhost`), and you're using a current browser with WebAuthn support (Chrome, Edge, Safari, Firefox).

### A previously working passkey no longer authenticates

Passkeys are bound to one Relying Party ID (domain). If the RP ID override, `APP_URL` or the sales channel domain changed, the user must re-register a passkey under the current domain. Authenticators without user verification (no PIN/biometrics) are refused, and a credential whose signature counter went backwards is disabled.

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SW6OIDC_REDIS_DSN` | *(unset)* | Optional. `redis://[[user]:password@]host:port[/db]` or `rediss://…` — one-time tokens in Redis instead of the database. Picked up at runtime; an unusable DSN falls back to the database and shows `redis_dsn_unusable` in the health endpoint. |
| `SW6OIDC_LOG_LEVEL` | `warning` | Base log level of the plugin's own log channel (`var/log/sw6oidc-<env>.log`, rotated daily, 14 files). The plugin setting **Enable debug logging** raises it to `debug`. |
| `SW6OIDC_HEALTH_TOKEN` | *(unset)* | If set, `/sw6oidc/health` requires this value in the `X-Sw6oidc-Health-Token` header (HTTP 401 otherwise). |
| `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` | `90` | Days after which session activity log entries are deleted (`0` = never). |
| `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP` | `0` | `1` stores session activity IP addresses truncated (IPv4 /24, IPv6 /64). |
| `SW6OIDC_ALLOW_PASSWORD_LOGIN` | `0` | `1` is a break-glass override that re-enables password login even when a provider disables it. |
| `SW6OIDC_ALLOW_USER_ACCESS_KEYS` | `0` | `1` allows `client_credentials` token requests with *user* access keys while admin password login is disabled. |
| `SW6OIDC_ALLOW_INSECURE_IDP_URLS` | `0` | `1` allows plain-http IdP URLs and private/loopback addresses (local development IdPs only — disables SSRF protection). |
| `APP_SECRET` | *(Shopware)* | The encryption keys for client secrets and stored security state are derived from it — keep it stable. |

`SW6OIDC_E2E_SHOP_IMAGE` and `SW6OIDC_E2E_SHOP_URL` are only used by the browser test suite (see [tests/E2E/README.md](tests/E2E/README.md)).

Behind a reverse proxy or CDN, also configure Shopware's `framework.trusted_proxies` (see [Rate limiting](#rate-limiting)).

## Command-Line Tools

```bash
# Export providers (incl. attribute/role mappings and access-control rules) as JSON — the client secret is omitted by default
bin/console sw6oidc:config:export -o providers.json [--force] [--provider-id=<id>] [--keep-encrypted|--plaintext]

# Import on another installation — validate first, then apply
bin/console sw6oidc:config:import -i providers.json --dry-run
bin/console sw6oidc:config:import -i providers.json [--overwrite] [--skip-unresolved]
```

`-o` creates the file with mode 0600 and refuses to overwrite an existing file unless `--force` is given. `--keep-encrypted` exports the encrypted secret, importable only where `APP_SECRET` is identical; `--plaintext` exports it readable (treat the file as a credential). ACL roles and customer groups are matched by id, then by name. Imports run the same validation as saving in the Administration (SSRF, lockout guard). `--overwrite` replaces only the mappings, rules and default references present in the file and warns about missing ones.

## Extension Points (Events)

Subscribe to these (all `ShopwareEvent`s) to customize JIT provisioning:

| Event | When | Can change |
|---|---|---|
| `MartinKuhl\Sw6Oidc\Event\AttributeMappingCompletedEvent` | Every OIDC login, after claims were mapped | The mapped profile (`setProfile()`) |
| `…\CustomerBeforeCreateEvent` / `…\AdminBeforeCreateEvent` | Right before a new account is created | The create payload (`setPayload()`; the admin payload includes `admin`/`aclRoles` — handle with care) |
| `…\CustomerAfterCreateEvent` / `…\AdminAfterCreateEvent` | After a new account was created and bound | — (read-only) |
| `…\PasskeyRegisteredEvent` | After a passkey was registered | — (also a Flow Builder trigger `sw6oidc.passkey.registered` and an audit log entry) |

JIT-created customers also trigger Shopware's own `CustomerRegisterEvent`. Changes an `AdminBeforeCreateEvent` listener makes to `admin`/`aclRoles` are logged; a changed email is reverted to the verified claim.

## Documentation

- **Technical documentation**: [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md) — guided tour for developers, gotchas, future improvements
- **Developer reference**: [CLAUDE.md](CLAUDE.md) — architecture, flow-by-flow internals, directory reference, and known implementation gaps
- **IdP setup guides**: [Authelia](Docs/authelia-sw6oidc-setup.md), [ZITADEL](Docs/zitadel-sw6oidc-setup.md), [Dex](Docs/dex-sw6oidc-setup.md)
- **Integration tests**: [tests/Integration/README.md](tests/Integration/README.md)
- **Browser E2E tests**: [tests/E2E/README.md](tests/E2E/README.md)
- **Static analysis and tests**: `composer ci` runs PHPCS, PHPStan (level 8 for `src/`, level 5 for `tests/`), Psalm (with unused-code detection and a baseline), Rector (dry run) and the unit tests
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

## Version

- **Plugin Version**: 0.1.0
- **Package**: `martinkuhl/shopware6-oidc-sso`
- **License**: MIT (see [LICENSE.txt](LICENSE.txt))
- **Requirements**: PHP 8.2 – 8.5, Shopware `>=6.7.15.0 <6.8.0.0`
