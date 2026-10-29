# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes (code review, revision 7)

- **Requires Shopware 6.7.15 or newer** (`>=6.7.15.0 <6.8.0.0`): the plugin uses core APIs that older 6.7 releases lack (`ResetOnClone`, `Choice`, `PreWriteValidationEvent::getCommandsForEntity()`). The old `>=6.7.0.0` constraint was wrong; installs on older 6.7 releases failed at activation.
- **Composer dependencies changed**: `web-token/jwt-library ^4.0` replaces `web-token/jwt-framework`; `league/oauth2-server`, `symfony/psr-http-message-bridge` and `nyholm/psr7` are no longer required directly. Run `composer update martinkuhl/shopware6-oidc-sso`.
- **`claim_encoding` is dropped** in the destructive migration step (replaced by `base64_claims` earlier).
- **The health endpoint returns only `status`** unless `SW6OIDC_HEALTH_TOKEN` is set and sent.
- **Providers with connected accounts can't be deleted through the plain DAL/API**; the Administration asks for confirmation and uses `POST /api/_action/sw6oidc/provider/{id}/delete`.
- **Provider fields are validated**: PKCE method and login type are fixed choices, HTTP timeout 1–60 s, JWKS cache TTL 60–86400 s.
- **At most 20 passkeys per account.** Forced logout of an admin session needs a superadmin.
- **Exceptions extend `Sw6OidcException`** with `SW6OIDC_*` error codes; the logger service id is `sw6oidc.logger`; `OidcCustomerLoginRoute` is removed.
- **The Administration uses Meteor (`mt-*`) components** instead of the deprecated `sw-*` ones.

### Fixed (code review, revision 7)

- SSO re-authentication (Administration step-up, Storefront reauth) failed against Authelia even with the correct password: the plugin sent `max_age=0`, which Authelia 4.39 always treats as "login required". Only `prompt=login` is sent now; `auth_time` is still checked.
- The Storefront passkey page crashed (`AccountPasskeyController` needed the concrete `LogoutRoute`, which the plugin decorates).
- ID tokens signed with PS*/ES* are accepted; `crit` headers, non-numeric `nbf`/`iat` and a missing nonce are rejected.
- Unknown or rotated customer context tokens no longer leave a session alive on IdP logout; hashed `sid` storage; Redis values are encrypted.
- Passkey signature counters are written compare-and-set; cross-site passkey requests are refused; registration options are rate-limited per customer.
- Emails are IDN-normalized and mapped fields are truncated to the column limits instead of failing the login.
- Log masking covers URL-encoded, JSON, Bearer/Basic and JWT values.

### Breaking changes (code review, revision 4)

- **Passkey credentials and account bindings are written by the plugin only.** The Admin and Sync API can no longer create them, re-point them at another account, or delete bindings (passkeys can still be renamed and deleted).
- **Trust-relevant provider settings need a superadmin**: endpoints, issuer, client ID, scope, public client, login type, claim handling, account linking, admin auto-creation, the default and superadmin role mappings, and the email/username mappings and access rules of providers serving the Administration. Every change is audit-logged. Creating a provider needs a superadmin too.
- **One SSO-only rule for every write.** Re-activating or re-scoping a provider, deactivating or deleting admins, unlinking an admin and changing an issuer are all checked against "an active admin can still log in through SSO". Unlinking an admin, confirming a lockout and confirming an issuer change need a fresh re-authentication.
- **Bindings include the issuer and compare `sub` byte-exactly.** Changing a provider's issuer with bound accounts asks whether to keep them connected or disconnect them. Customers bound to a sales channel get one binding per channel.
- **Role sync is multi-valued and only touches roles it granted** (`sw6oidc_managed_acl_role`, seeded on update). Provider defaults apply to new accounts only. Admins are never linked to an existing account by email, nor upgraded from a legacy binding.
- **Storefront "Connect SSO" and passkey registration need a freshly authenticated browser session** (any login, or a verified re-authentication, within 10 minutes).
- **Logout style is an explicit provider setting** (`standard` or Authelia's `?rd=` portal logout) instead of a guess from the URL. Existing Authelia-shaped endpoints keep the portal logout; Keycloak, Auth0, Okta and Entra ID endpoints switch to the standard logout. The standard logout always sends `client_id`.
- **`passkeyRpId` is per sales channel; the Administration has its own `passkeyRpIdAdmin`.** Both are validated on save.
- **Public clients need no client secret** (the column is nullable); confidential clients must have one, and a cloned provider never inherits it.
- **While a verified email is required, the email mapping must be the untransformed `email` claim** (refused at save time).
- Admin token, passkey and step-up endpoints build the OAuth request on the server; the client sends only the nonce or assertion. Anonymous endpoints never answer 401.

### Fixed (code review, revision 4)

- Admin passkey login, the inactivity passkey and both step-up methods failed with `unsupported_grant_type`.
- The provider detail page crashed on every open; role privileges never registered in the role editor.
- Deleting one Storefront passkey could delete a different one; deleting a passkey now ends the sessions it logged in.
- IdP back-channel logout missed admins active for longer than the refresh-token TTL, treated Redis error replies as replays, and could not be retried after a failure.
- Anonymous logout tokens with random `kid`s forced unlimited JWKS fetches; redirects were followed despite `max_redirects: 0`.
- First-login races left duplicate accounts; JIT customers ignored the sales-channel binding; placeholder addresses could reach orders.
- One-time tokens are pruned hourly in batches; password-session revocation skips guests and runs from the message queue.
### Breaking changes (code review, revisions 1-3)

- **Accounts are bound to the IdP subject, not the email address.** Logins resolve the account by `(provider, iss, sub)`. Existing email-only bindings get their `sub` filled in on the next login with a verified email. An existing, unbound account is only linked when the new provider option **Link existing accounts by verified email** is on (default off; never for superadmins); otherwise the user connects SSO from the customer account or the admin profile (**Connect SSO**).
- **`email_verified` is required** by default (`require_email_verified`, per provider). A missing claim counts as unverified.
- **`openid` scope means an id_token is required.** Userinfo must describe the same `sub`; `sub`, `email` and `email_verified` always come from the id_token.
- **Providers are scoped by login type.** A customer-only provider can no longer be used for Administration logins and vice versa.
- **Password re-confirmation can no longer be skipped.** The `verify-session` endpoint and the decorator that switched Users & Permissions into "native SSO mode" are removed. Re-confirmation now offers **Confirm with SSO** (fresh IdP login) or **Confirm with passkey** next to the password; both mint a 5-minute, non-refreshable `user-verified` token. Login endpoints never grant `user-verified`.
- **Passkeys require user verification** (PIN/biometrics), exact origins, and an RP ID from `APP_URL` (Administration) or the sales channel domain (Storefront). Registering a passkey needs a recent login (customers) or step-up (admins). A passkey whose signature counter goes backwards is disabled as a possible clone. The Administration passkey login is always usernameless.
- **Security state moved from `cache.app` to the database** (`sw6oidc_session`, `sw6oidc_one_time_token`, `sw6oidc_node_heartbeat`). Clearing the cache no longer breaks logins or logouts. `SW6OIDC_REDIS_DSN` is an optional accelerator; the plugin warns when several nodes run without it.
- **Default log level is `warning`.** The **Enable debug logging** setting now switches the `sw6oidc` channel to `debug`; `SW6OIDC_LOG_LEVEL` sets the base level. Logs rotate (14 files) and mask tokens, secrets and sensitive query parameters.
- **New encryption envelope `sw6oidc_v2:`** (XChaCha20-Poly1305, one key per field, field bound as associated data). `v1` is still read; a migration re-encrypts stored secrets. Exports with `--keep-encrypted` from older versions still import.
- **Access-control rule semantics are stricter.** `eq` matches any list entry; `neq` and `not_contains` deny when the claim is missing; `contains` on a single value matches a whole token, never a substring. New operators `ends_with` and `email_domain` (use the latter to restrict by domain). Unknown operators are rejected on save.
- **`claim_encoding = base64` is replaced by a list of base64-encoded claims** (`base64_claims`). Providers that used base64 are migrated to `["*"]` (all claims); narrow the list to the claims that are actually encoded.
- **Role sync replaces roles** instead of adding them. The new option **Revoke superadmin on SSO** lets sync also remove superadmin (never from the last active superadmin).
- **Changing a token, revocation, userinfo or discovery URL requires re-entering the client secret** in the same save.
- **SSO-only customer mode also blocks registration** (Storefront and Store API; guest checkout stays allowed), and **client-credentials logins with a user access key** are blocked in admin SSO-only mode unless `SW6OIDC_ALLOW_USER_ACCESS_KEYS=1`.
- **Logins and admin login nonces are bound to the browser** that started them (HttpOnly, SameSite=Lax cookie).
- **Force logout needs the new privilege `sw6oidc_session_activity:force_logout`**; the session activity log can't be edited or deleted through the API.
- **`sw6oidc:config:export -o` refuses to overwrite** an existing file without `--force` and creates it with mode 0600. `--plaintext` fails instead of exporting an undecryptable envelope.
- **`button_label` / `button_color` are dropped** in the destructive migration step (never read).
- **Behind a reverse proxy or CDN, configure `framework.trusted_proxies`.** Rate limits are kept per client address.
### Breaking changes (earlier in this release)

- **IdP URLs must be HTTPS on a public address.** Provider URLs over plain http or resolving to a private, loopback, link-local or similar address are rejected on save and on every outbound request. Set `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1` for local development IdPs.
- **"Disable non-OIDC admin/customer login" is now enforced.** It used to be stored but ignored. It now really blocks password login (Storefront, Store API, Admin `password` grant). It can only be switched on once an account of that type has signed in through the provider. The break-glass override is `SW6OIDC_ALLOW_PASSWORD_LOGIN=1`.
- **The client secret is write-only in the Admin API.** It is no longer returned after saving. Leave the field empty to keep the stored secret.
- **Keep `APP_SECRET` stable.** Stored client secrets are encrypted with a key derived from it. After rotating it, every provider's secret must be entered again.
- **The per-attribute `sync_on_sso` column is removed** (in the destructive migration step). It was never read. Re-sync is controlled by the provider-level toggles.
- **`web-auth/webauthn-lib` is now `^5.3`** instead of `^4.7`. Passkeys stored by 4.x keep working.

### Added (code review revision 2)

- Browser E2E suite (`tests/E2E`, Playwright, dockware + Dex, virtual WebAuthn authenticator) and non-blocking CI jobs `e2e` and `assets` (fails on a stale committed storefront bundle).
- Health endpoint statuses `ok` / `degraded` (200) / `down` (503), 30 s cache, optional `SW6OIDC_HEALTH_TOKEN` (header `X-Sw6oidc-Health-Token`), and infrastructure warnings (`redis_dsn_unusable`, `multi_node_without_redis`), also in the diagnostics panel.
- ACL privilege mapping for the provider, passkey and session modules, so they can be granted to ordinary roles.
- RP-initiated logout revokes the real IdP tokens; the Store API logout response carries the IdP logout URL.
- Account deletion removes the plugin's per-account data (binding, passkeys, sessions, activity); deactivation ends all sessions. `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP=1` stores truncated IP addresses.
- `CustomerRegisterEvent` is dispatched for SSO-created customers (Flow Builder).
- The live login test runs the login's claim rules, group normalisation and an access-control preview.

### Changed (code review revision 2)

- Rate limiting: separate budgets per endpoint group; flow start and passkey options count every request (30/min), redeem endpoints count failures (10/min); IPv6 addresses share a budget per /64; callbacks with an unknown state don't count.
- JWT verification selects keys by `kid`, refetches the JWKS only for an unknown `kid`, allows 60 s clock leeway, requires `iat`, checks `azp`. Back-channel logout tokens need `jti` and an `iat` at most 5 minutes old; front-channel logout ends admin sessions only with the new provider option.
- Avatars are fetched through the SSRF-guarded client and skipped when unchanged; outbound requests follow no redirects by default.
- Admin token lifetimes follow `shopware.api.access_token_ttl` / `refresh_token_ttl`.
- Expired sessions show as "Expired (no logout recorded)" instead of "Active".

### Removed (code review revision 2)

- `ClaimsNormalizer::extractEmail()`, `TokenExchangeService::refreshAccessToken()`, `ProviderResolver::hasVisibleProvider()`, `CachePoolAtomicCache`, the `verify-session` endpoint, and the account-overview template override.
### Added

- Setup guides for Authelia, ZITADEL and Dex (`Docs/`).
- Integration test suite (`tests/Integration/`, `composer test-integration`): a real Shopware 6.7 kernel and database plus Dex as the IdP — Back-Channel Logout, full Storefront and Administration OIDC logins, and access-control rules against real claims — and a fifth CI job running it. Not yet run; the CI job is non-blocking until it passes.
- Health checks and alerting: `GET /sw6oidc/health` for uptime monitors (configuration and last scheduled check, no outbound calls, counts only); a **Run diagnostics** panel per provider (`POST /api/_action/sw6oidc/provider/{id}/diagnostics`); and a scheduled reachability check (every 5 minutes) that POSTs one webhook alert per outage after a configurable number of consecutive failures, with an optional recovery message. The webhook URL is stored encrypted and SSRF-checked.
- Session activity log (`sw6oidc_session_activity`) and a new Administration module *OIDC & Passkey sessions*: every OIDC/Passkey login with provider, IP address, user agent, logout time and reason (logout, back-/front-channel, forced), an "only active" filter and a **Force logout** action (`POST /api/_action/sw6oidc/session-activity/{id}/force-logout`, ACL `sw6oidc_session_activity:force_logout`). A daily scheduled task deletes entries after `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` (default 90).
- Per-provider **Post-logout redirect URI** (`post_logout_url`) for RP-initiated logout, and a shared landing page `/sw6oidc/postlogout` for IdPs that accept only one post-logout URI: it sends customers to the Storefront login and admins to the Administration, based on a signed `state`.
- Administration RP-initiated logout now takes the provider and id_token from the session registry (the current session, else the newest), with the previous per-user store as fallback. Storefront logout removes its session from the registry.
- OIDC Front-Channel Logout (`GET /sw6oidc/frontchannel-logout?iss=…&sid=…`): ends the shop sessions of an IdP session from the IdP's logout page iframe; always answers with a 1×1 GIF. Unknown `sid`s count toward the rate limit.
- OIDC Back-Channel Logout (`POST /sw6oidc/backchannel-logout`): the IdP can end shop sessions server-to-server. Logout tokens are fully verified (signature, `iss`/`aud`/`exp`, `events`, no `nonce`, `jti` replay protection). Customers lose exactly the affected session; Administration users lose all their sessions (admin access tokens can't be revoked individually).
- Rate limiting for the unauthenticated endpoints (see *Changed* above for the current budgets).
- Session/subject registry: every OIDC login records which local session it created (Storefront context token / Administration access-token jti), indexed by the IdP subject, the IdP session id (`sid`) and the local account. Groundwork for Back-/Front-Channel Logout and forced logouts; no visible behavior on its own.
- Claims-based access control: per-provider rules (`eq`, `neq`, `contains`, `not_contains`, `exists`, `not_exists`) that all must pass before a login is accepted, evaluated before any account lookup or JIT provisioning. List claims are matched by entry, comparisons ignore case, and each rule carries its own denial message (shown on the Storefront and, via a one-time error ticket, on the Administration login screen). New table `sw6oidc_access_control_rule`, an **Access control** card on the provider detail page, and export/import support.
- `client_secret` is encrypted at rest (libsodium secretbox, `sw6oidc_v1:` envelope). A migration encrypts existing rows.
- Save-time SSRF validation for every fetched provider URL. A runtime `NoPrivateNetworkHttpClient` guard checks every connection and redirect.
- Enforcement of the password-login flags, with a lockout guard. The password form is hidden on the Storefront and Administration login screens while password login is disabled.
- Attribute value transforms per mapping: `concat`, `split`, `prefix`, `regex_replace`. They can be edited in the attribute mapping grid.
- Domain events around JIT provisioning: `AttributeMappingCompletedEvent`, `CustomerBeforeCreateEvent`/`CustomerAfterCreateEvent`, `AdminBeforeCreateEvent`/`AdminAfterCreateEvent`.
- CLI commands `sw6oidc:config:export` and `sw6oidc:config:import` (dry run, overwrite, reference resolution by id or name, secret omitted by default).
- A JWKS circuit breaker: a failed fetch pauses further fetches for 60 s. A token signed with an unknown key triggers one refetch, so IdP key rotation no longer locks users out until the cache TTL runs out.
- Redis-backed atomic one-time-token cache. It is selected at runtime whenever `SW6OIDC_REDIS_DSN` is set (`redis://` or `rediss://`). No DI override is needed any more.
- The IdP origins are added to directives an existing Content-Security-Policy already declares.
- Field-level error messages in the provider form for rejected URLs and the lockout guard.
- Unit tests for the OIDC core (state/PKCE/nonce, JWT verification, claims normalization), both provisioning services, group mapping, bindings, the WebAuthn ceremonies (real 5.x validators) and every new component.

### Changed

- The RP-initiated logout `state` parameter is now HMAC-signed (`customer.<random>.<sig>` / `admin.<random>.<sig>`) instead of `customer:<random>` / `admin:<random>`.
- The live login test popup is translated (German/English, following the Administration UI language) and styled like the provider detail page's result card. It reads the Administration snippet files, so both use the same wording.
- Test status labels are aligned across the plugin ("Erfolgreich"/"Fehlgeschlagen", "Passed"/"Failed"), and the provider list's "Test status" column uses the same pill style as the detail page.

### Fixed

- The Administration's inactivity re-login modal ("Um sicherzugehen, haben wir dich abgemeldet") only offered password and passkey. It now shows one **Login with <provider>** button per admin SSO provider, and after the OIDC round trip the admin returns to the page they were on. With password login disabled for admins, the modal's password field and button are hidden.
- The passkey ceremony unit test failed in ~1 of 128 runs (EC public-key coordinates with a leading zero byte were not padded to 32 bytes by the test authenticator).
- Opening the OIDC provider settings failed with `TypeError: J is not a function`.
- A group literally named `"0"` was dropped from a groups claim. Integer group ids are now kept.
- The flattened-claims key limit accepted one key more than intended.
- A failed Redis save made the one-time token unreachable, because the fallback store was never consulted on read.
- The JWKS response was cached before it was known to parse.
- Upgrading to webauthn-lib 5.x also fixes advisory GHSA-gq4g-fpc9-vjfq, which affects 4.9.x.

## [0.1.0]

- Initial release: multi-provider OIDC SSO for the Storefront and Administration with JIT provisioning and group/role mapping, plus Passkey (WebAuthn) login.
