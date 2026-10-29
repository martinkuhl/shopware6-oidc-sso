# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Shopware 6 plugin (`MartinKuhl\Sw6Oidc`, composer package `martinkuhl/shopware6-oidc-sso`, currently v0.1.0) that provides OpenID Connect (OIDC) and Passkey (WebAuthn/FIDO2) single sign-on for both Storefront customers and Administration users. It mirrors the architecture of the sibling `magento2-oidc-sso` module: multi-provider OIDC with JIT provisioning and group/role mapping, plus a second, independent passwordless login method (Passkey) that bridges into native authentication the same way OIDC does.

The plugin is early-stage (v0.1.0, MIT license) with three test layers: a unit suite (OIDC core, provisioning, WebAuthn, every security component), an integration suite against a real Shopware kernel and Dex, and a Playwright browser E2E suite. `Code-Review.md` holds the code review (revision 7: open findings only, every earlier finding is fixed or decided; fixed findings are in git history); finding ids (`N-H1`, `M10`, `R3-H1`, …) appear in code comments and commit messages. `Code-Review_implementation_plan.md` lists what is still open. See "Known gaps / implementation notes" below before assuming a feature is fully wired end to end.

## Development commands

### Composer scripts (`composer.json`)
```bash
composer test              # phpunit (unit suite)
composer test-coverage     # phpunit with HTML + Clover + text coverage
composer phpstan           # phpstan analyse -c phpstan.neon.dist (src, level 8)
composer phpstan-tests     # phpstan analyse -c phpstan.tests.neon.dist (tests/Unit, level 5)
composer psalm             # psalm (errorLevel 4, unused code against psalm-baseline.xml)
composer rector            # rector process --dry-run
composer rector-fix        # rector process (applies fixes)
composer cs-check          # phpcs (PSR12-based ruleset)
composer cs-fix            # phpcbf
composer ci                # cs-check -> phpstan -> phpstan-tests -> psalm -> rector -> test
SHOPWARE_PROJECT_ROOT=/path/to/shop composer test-integration   # integration suite, see tests/Integration/README.md
cd tests/E2E && npm install && npm run env:up && npm test        # browser E2E, see tests/E2E/README.md
```

### Plugin lifecycle
```bash
bin/console plugin:refresh
bin/console plugin:install --activate Sw6Oidc
bin/console plugin:update Sw6Oidc
bin/console cache:clear
```
Schema is **migration-driven**, not `install()`-driven — `Sw6Oidc.php` has no custom `install()`/`activate()`/`deactivate()`, only `uninstall()`. Table creation happens the first time migrations run (automatically during `plugin:install`, or explicitly via):
```bash
bin/console database:migrate Sw6Oidc --all
bin/console database:migrate-destructive Sw6Oidc --all   # drops removed columns (sync_on_sso, button_label/button_color)
```

### Provider config export/import (`Console/`, logic in `Service/Config/OidcConfigTransfer`)
```bash
bin/console sw6oidc:config:export [--provider-id=<id>] [-o file.json [--force]] [--keep-encrypted|--plaintext]
bin/console sw6oidc:config:import -i file.json|- [--dry-run] [--overwrite] [--skip-unresolved]
```
- Versioned JSON (`version: 1`): provider fields + attribute/role mappings + access-control rules; `last_test_*`/timestamps, the health-alert webhook URL (secret) and health-alert state are left out. ACL roles/customer groups are exported as `{id, name}` and resolved on import by id, else unique name (otherwise the provider fails, or with `--skip-unresolved` the reference/row is dropped).
- Client secret **omitted by default**; `--keep-encrypted` exports the stored envelope (only importable where `APP_SECRET` is identical — the field serializer rejects foreign envelopes; legacy plaintext rows are encrypted on the fly, never exported raw), `--plaintext` the decrypted value via `getUsableClientSecret()` (never an undecryptable envelope). An import without a secret keeps the stored one; a *new* confidential provider without one fails.
- `-o` creates the file `0600` with O_EXCL semantics (no following existing files/symlinks); an existing file is only replaced with `--force` (unlinked first).
- Matches providers by `id`; existing ones are skipped unless `--overwrite`. Overwrite replaces only the child collections (`attributeMappings`/`roleMappings`/`accessControlRules`) and default references **present in the file**, warning about missing keys — a hand-edited file can never silently drop rules. Per-provider transaction. Writes go through the repository, so encryption and `Sw6OidcProviderWriteGuardSubscriber` apply (CLI writes count as lockout-confirmed). `--dry-run` wraps the whole import in a rolled-back transaction.

## Architecture — OIDC flow

Two independent SP-initiated entry points share all downstream machinery:
- Storefront: `GET /sw6oidc/login` (`SendAuthorizationRequestController`) → IdP → `GET /sw6oidc/callback` (`OidcCallbackController`)
- Admin: `GET /api/sw6oidc/admin/login` → IdP → `GET /api/sw6oidc/admin/callback` (`OidcAdminAuthController`)

Both start routes resolve the provider via `ProviderResolver::getActiveById($id, $loginType)` (or `resolveDefault($loginType)`): a provider is only usable for the login type it serves (`customer`/`admin`/`both`) — a customer-only IdP can never start an Administration login, and vice versa (C1). Flow start consumes the `flow_start` rate-limit budget.

1. **`AuthorizationRequestBuilder::build()`** calls `OidcSecurityHelper::beginAuthorizationRequest()`, which generates state, PKCE `code_verifier`, and nonce (all `random_bytes` base64url), bundles them into an `AuthorizationFlowContext` (`providerId`, `loginType`, `relayState`, `codeChallengeMethod`, `purpose` = `login`|`link`|`step_up`, `expectedUserId`, start time, `browserBinding` hash) and stores it in `AtomicCacheInterface` under `sw6oidc_flow_{state}` (600s TTL). Code challenge: `plain` or `S256` per provider. PKCE is always used. `extraParams` carries `prompt=login` for step-up/re-auth. `relayState` (Storefront redirect target) is validated by `RelayStateValidator` at start and again at the callback (strict same-origin absolute path, checked raw and percent-decoded, or a `frontend.*` route name + parameters; else the account page) (H4).

2. **Browser binding (M1)** — `Service/Security/BrowserBinding`: flow start mints a random value, stored in an HttpOnly, SameSite=Lax cookie (`__Host-sw6oidc_binding` on HTTPS, else `sw6oidc_binding`, 30 min, reused across tabs) set on the response by `Subscriber/BrowserBindingCookieSubscriber`; the flow (and the admin login nonce) stores only its hash. `consumeAuthorizationFlow()` and `AdminLoginNonceService::redeemNonce()` refuse a different browser (login CSRF / nonce hand-off protection). Outside an HTTP request (CLI/tests) the hash is null and always matches.

3. **`OidcCallbackProcessor::process(code, state, redirectUri, expectedLoginType)`** is the single pipeline shared by both callbacks ("so the two flows can never drift"):
   - `OidcSecurityHelper::consumeAuthorizationFlow($state)` — atomic get-and-delete; missing/unknown/expired state throws `UnknownStateException` (subclass of `InvalidStateException`; **not** counted by the rate limiter, N-M3), corrupt state or a foreign browser throws `InvalidStateException`.
   - A flow started for the other login type is rejected (C1); flow context is validated strictly on hydration (L10).
   - Resolves the provider via `getActiveById(flow->providerId, flow->loginType)` (re-checked: it may have been deactivated/re-scoped meanwhile).
   - `TokenExchangeService::exchangeCodeForTokens()` — POSTs code + PKCE verifier; `client_secret` (from `getUsableClientSecret()`, `ClientSecretUnavailableException` if undecryptable) only for confidential clients (RFC 6749 §2.1), sent per the provider's `token_endpoint_auth_method` (`client_secret_basic` default, or `client_secret_post`; built by `ClientAuthentication`, shared with revocation). `access_token` required.
   - `id_token` present → `JwtVerifier::verify()` (see below). Absent while the provider's scope contains `openid` → `InvalidStateException` (OIDC Core §3.1.3.3). Only a provider without `openid` relies on userinfo alone (warning).
   - `UserInfoService::fetchClaims()` — GET with `Authorization: Bearer`; `[]` if no userinfo endpoint.
   - `ClaimsMerger::merge()` (M2): userinfo wins in general, but if both are present userinfo `sub` must equal the id_token `sub` (else `InvalidStateException`), and `sub`/`email`/`email_verified` always come from the id_token when it has them. A missing `sub` fails the login (`ClaimsMerger::requireSubject()`, R3-L4). `ClaimsMerger` is shared with the live login test.
   - Extracts the **raw, unflattened** groups claim, `ClaimsNormalizer::normalizeGroups()` then `decodeGroups()` **before** flattening — flattening a Zitadel-style nested role object (`{"Engineering": {"orgId": "..."}}`) would turn group names into dotted leaf paths.
   - `ClaimsNormalizer::flatten($claims, $provider->getBase64Claims())` — recursive dot-notation (max depth 5, max 2000 keys, else `ClaimsTooComplexException`); base64-decodes only the claims listed in the provider's `base64_claims` (a name covers itself and everything nested under it, `"*"` = all — the old `claim_encoding=base64` behaviour, M10). Group names are decoded through the same list, so groups and access-control rules agree.
   - `Sw6OidcAccessControlEvaluator::evaluate()` — claims-based access-control rules; throws `AccessControlDeniedException` before anything is looked up, created or synced.
   - `AttributeMapper::map()` → `MappedProfile`. Returns `OidcCallbackResult` (provider, flow, profile, tokens, id_token claims, merged claims; `identity()` → `ExternalIdentity`, `sessionId()` = `sid` from the verified id_token only, `idToken()`/`idpAccessToken()`/`idpRefreshToken()`).

   `process()` = `consumeFlow()` + `processFlow()`: the admin callback calls them separately, so a failing step-up flow still answers through its popup (`{type: 'sw6oidc-step-up', error}`, R3-F9). An IdP error response (`?error=`) ends its flow (`abortFlowWithIdpError()`), is logged truncated at notice level, and counts on the callback budget only without a flow of this browser (R4-L4).

   The callbacks then dispatch on `flow->purpose`: `login` → provisioning + login; `link` → `IdentityResolver::linkExplicitly()` for `flow->expectedUserId` (see Identity); `step_up` (admin only) → `StepUpService::completeOidc()`.

4. **JWT verification (`JwtVerifier::verify`)** — via `web-token/jwt-library`. `RS256/384/512`, `PS256/384/512` and `ES256/384/512` (`SUPPORTED_ALGORITHMS`, R4-L3); discovery and the connection test flag an IdP that advertises none of them. A `crit` header is refused (R4-L1). JWKS cached in `cache.app` (keyed by sha256 of the JWKS URL, TTL = provider's `jwks_cache_ttl`); a failed fetch sets a 60s circuit breaker. **Key selection**: only keys of the algorithm's type (RSA, or EC with the matching curve) with `use` absent/`sig`, `alg` absent/matching and — if the token names one — the token's `kid`. A forced JWKS refetch happens only when the `kid` is missing from the cached set (rotation), limited per cooldown window per endpoint + `kid` for logins and per endpoint only for anonymous logout tokens (R3-M1); `kid` > 256 bytes is refused; logout and login use separate fetch breakers; a bad signature with a known key is just forged and never costs a refetch, and back-channel tokens without `kid` never refetch (N-H2). Claims: `exp`/`nbf`/`iat` with `LEEWAY_SECONDS = 60` (a present non-numeric `nbf`/`iat` is invalid, R4-L2), `iat` **required** and not in the future, `iss` exact, `aud` string-or-array, `azp` must equal the client id when there are several audiences or an `azp` claim (M11), `nonce` exact and mandatory (R3-L7).

5. **Admin OIDC ↔ League OAuth2 bridge** (`Service/AdminAuth/`) — rather than reimplementing Shopware's admin token issuance, the plugin runs a **second**, plugin-owned `League\OAuth2\Server\AuthorizationServer` wired to Shopware core's own `ClientRepository`/`AccessTokenRepository`/`ScopeRepository`/`FakeCryptKey` plus `APP_SECRET`, so its tokens are indistinguishable from a password-grant login.
   - `AdminOidcGrant` (grant identifier `sw6oidc_admin`) reads a **pre-verified** user id off a PSR-7 request attribute (`REQUEST_ATTRIBUTE_USER_ID`); no password check inside — trust comes from the caller. `validateUser()` refuses deleted and inactive users for every caller (H1). `user-verified` is stripped from the requested scopes unless `REQUEST_ATTRIBUTE_STEP_UP` is set (N-M17); step-up mode issues `write user-verified`, access TTL ≤ 5 min, no refresh token.
   - `AdminTokenIssuer::issue($userId, $stepUp = false)` — the one place that builds the grant request. It builds a fresh PSR request (`grant_type`, `client_id=administration`, `scope=write`) and never converts the client's request: the PSR bridge builds a JSON body from the raw content and ignores the parameter bag (R3-H1). Used by nonce exchange, passkey login and step-up; `AdminTokenIssuerTest` runs a real League server.
   - `AdminAuthorizationServerFactory` exists because `enableGrantType()` needs a `\DateInterval`; access/refresh TTLs come from `shopware.api.access_token_ttl`/`refresh_token_ttl` (H10). Registered under the plugin's own service id, never aliased to the bare `AuthorizationServer` class id (would collide with core's `/api/oauth/token`).
   - `AdminLoginNonceService` bridges the full-page redirect back into the SPA: 120s-TTL nonce (`AdminLoginNonce`: user id, provider id, pending registry session id; the browser-binding hash is checked on redemption) → `{administrationBaseUrl}/#/login?sw6oidc_nonce=...` → the `sw-login` override POSTs it to `POST /api/sw6oidc/admin/token` → `exchangeNonce()` redeems (same browser only, failures count on the `redeem` budget; the client sends only the nonce), issues the token, activates the registry entry with the access token's jti and adds `sw6oidc_login_session` (registry id) to the token JSON. JS then installs the token via `service/login-completion.js` (honours "remember me", resets the inactivity clock, F-M1) and forces a reload/router push (otherwise the SPA's modules/menu stay uninitialized).
   - Admin Passkey login uses `AdminTokenIssuer` directly (same-page AJAX ceremony, no nonce).

6. **Logout** — `RpInitiatedLogoutService`, shared:
   - `buildLogoutUrl(provider, idToken, defaultPostLogoutRedirectUri, target)` returns `null` without `end_session_endpoint`. The provider's `post_logout_url` replaces the default redirect; `state` is `PostLogoutState::create(target)` (`customer`/`admin`, HMAC from `APP_SECRET`). The provider setting `logout_style` decides the format: `standard` (always `client_id`, `id_token_hint` when known, `post_logout_redirect_uri`, `state`) or `authelia_forward_auth` (`?rd=`). No URL guessing any more (R3-M3; migration 16 kept Authelia-shaped endpoints on the portal logout).
   - **Shared landing** — `Controller/Oidc/PostLogoutController` (`GET /sw6oidc/postlogout`): valid `admin` state → `{APP_URL}/admin/`, else `frontend.account.login.page`. `post_logout_url` is validated by the write guard as an absolute http(s) URL (`SW6OIDC_REDIRECT_URL_INVALID`), not SSRF-checked.
   - `revokeTokens(provider, LogoutContext)` — RFC 7009 revocation of the login's IdP refresh token, then access token (M14); client authentication per the provider's own `revocation_endpoint_auth_method` (Authelia registers it separately from the token endpoint's); fire-and-forget, failures logged.
   - Storefront logout, two steps: `Storefront/Service/OidcLogoutRoute` decorates core `LogoutRoute`, captures the **pre-logout** context token + customer id, delegates, looks up the registry entry via `findBySessionKey()` and removes it, records the activity logout, revokes the IdP tokens, builds the logout URL and hands it to `PendingLogoutRedirect`; Store API clients get it as `redirectUrl` in the `ContextTokenResponse` (H11). Can't be a `CustomerLogoutEvent` listener (core swaps the context token first). `CustomerLogoutSubscriber` (`KernelEvents::RESPONSE`) turns it into a redirect only on `frontend.account.logout.page`.
   - Admin logout: the `sw-admin-menu` override POSTs `/api/sw6oidc/admin/logout` (auth required) with `sw6oidc_login_session` (`service/login-session.js`). `consumeAdminLogoutContext()` removes **exactly** that registry entry (by login-session handle, else by the current jti); without an exact match nothing is removed (N-M4) and `LogoutContextStore::consumeForAdmin()` (provider of the admin's last login, no id_token) still yields a logout URL. Returns `{"logoutUrl": string|null}`; only http(s) URLs are followed by the JS (F-N14), failures fall through to core's stock logout. The `sw-inactivity-login` override adds SSO/passkey buttons; the SSO round trip carries a 32-hex return id as `relayState` (`service/sso-return-route.js`: entry tied to one round trip, internal paths only, remembers the expected admin; F-N9/F-N10/F-N1) and clears core's per-tab entries (F-N13); `sw-login` only resumes the old session (return route, `session_channel` broadcast) for the same admin.
   - IdP-initiated logout: see below.

## Architecture — Back-/Front-Channel Logout & rate limiting

- **`Controller/Oidc/BackChannelLogoutController`** — `POST /sw6oidc/backchannel-logout` (storefront scope, unauthenticated, `logout_token` form field). `decodeUnverified()` for `iss`/`aud` → `ProviderResolver::findByIssuer()` → first whose `clientId` is in `aud` → per-provider `isBlocked()` (a blocked caller is verified against cached keys only, R3-M1) → `verifyLogoutToken()` → `jti` replay marker via `AtomicCacheInterface::addIfAbsent()` (`sw6oidc_bcl_jti_<sha256(iss,jti)>`, until `exp` + leeway, 60s..24h; a replay answers 200 without acting) → `Sw6OidcIdpLogoutHandler::logout(providerId, sub, sid, 'backchannel')`. If the logout fails, the marker is deleted and the answer is 500, so the IdP retry is processed (R3-M19). Anonymous callers only ever see a fixed `400 {"error":"invalid_request"}` (N-L1). Unresolvable tokens count on the `backchannel_logout` scope and, once it is used up, are answered 429 without another log line (R3-L8); signature/claim failures count per provider (`backchannel_logout:<providerId>`) and address and answer 429 once blocked — a correctly signed token is never refused (shared SaaS egress IPs, N-M7). 200 + `no-store` on success.
- **`JwtVerifier::verifyLogoutToken()`** — same signature/`exp`/`nbf`/`iss`/`aud` checks (own refetch cooldown namespace), plus `iat` present and ≤ `LOGOUT_TOKEN_MAX_AGE_SECONDS` (300) old, `jti` required (N-L2), `events[BACKCHANNEL_LOGOUT_EVENT]` object, `sub` or `sid`, and **no** `nonce`. `typ` not checked.
- **`Controller/Oidc/FrontChannelLogoutController`** — `GET /sw6oidc/frontchannel-logout?iss=&sid=`. Both parameters required (SameSite cookies never reach a cross-site iframe); every `findByIssuer()` provider is tried with `includeAdmins = $provider->isFrontchannelAdminLogout()` — admin sessions are only ended with the `frontchannel_admin_logout` opt-in (N-M5), customers always. **Always** 200 + 1×1 GIF + `no-store` + `frame-ancestors *`. Only malformed requests count as failures and only they are ever blocked, so junk from a shared NAT can't drop real logouts (R3-L9); ending nothing is normal and not counted (N-M6).
- **`Service/Session/Sw6OidcIdpLogoutHandler::logout(providerId, ?sub, ?sid, reason, includeAdmins = true)`** — `sid` given → `resolveBySid()` (filtered to `sub` when both are present), else `resolve(sub)`; destroys each session first and only then removes its entry (R3-M19) (admin once per user, then **all** of that admin's registry entries are dropped, N-L3), records the activity logout. Returns the ended sessions.
- **`Service/Security/Sw6OidcRateLimiter`** — Symfony `RateLimiterFactory` built in the class (plugins can't join core's `shopware.api.rate_limiter`), fixed window per scope + client address (`Request::getClientIp()`, IPv6 keyed by its /64), `CacheStorage` on `cache.rate_limiter` (`on-invalid="null"` → `cache.app`), no lock. **Two budgets per scope**:
  - consuming — `consume()`, 30/60s, every request counts: flow start (storefront + admin, `flow_start`) and both passkey login-options (`options`), whose *successful* requests create state (N-M15, M5);
  - failure-only — `isBlocked()` peeks, `recordFailure()` counts, 10/60s: `callback_storefront`/`callback_admin` (generic `\Throwable` path only; unknown state, access-control and account-policy denials don't count), `redeem` (nonce exchange, both passkey login-verify, login-error tickets; step-up per admin), `backchannel_logout`, `frontchannel_logout`.
  - Behind a proxy/CDN, `framework.trusted_proxies` **must** be configured, or all clients share the proxy's budget.

## Architecture — State storage (one-time tokens, session registry)

Security state lives in the database, not in cache pools that `cache:clear`, deploys or evictions empty (N-H3, M4).

- **`AtomicCacheInterface`** (`save`, atomic `getAndDelete`, atomic `addIfAbsent`, `delete`) — OAuth flow state, admin login nonces, step-up nonces, WebAuthn ceremonies, admin logout contexts, login-error tickets, back-channel `jti` markers. Always aliased to `RedisAtomicCache`, which picks its backend **at runtime** (not a compiler pass — that would freeze into the cached container):
  - `SW6OIDC_REDIS_DSN` (`redis://`/`rediss://`) set, ext-redis loaded, connection OK → Redis: reads via a GET+DEL **Lua script** (atomic on every server version, N-M13), `addIfAbsent()` via `SET NX EX`. Optional accelerator. phpredis answers error replies (OOM, READONLY, MISCONF) with `false`: `false` plus `getLastError()` is an error and falls back to the database, never "already seen" (R3-M18). This Redis must use `maxmemory-policy noeviction` (`redis_may_evict` warning).
  - Values are encrypted in Redis too (same purpose as the DB store; plaintext from before is still read, R3-L35).
  - otherwise, and per call on any Redis error → **`DatabaseAtomicCache`** (`sw6oidc_one_time_token`): key hashed, value encrypted (purpose `sw6oidc_one_time_token.value`), `getAndDelete()` = `SELECT … FOR UPDATE` + delete in one transaction; expired rows invisible, pruned hourly by `sw6oidc.one_time_token_cleanup` in batches of 5000 within 30 s (R3-M17). `getAndDelete()` on Redis falls back to the DB on a miss (value saved there during a Redis error).
  - `RedisConnectionFactory`: persistent connection, 1.5s connect/read timeouts, AUTH/SELECT results checked, an unusable DSN logged as a warning, a failed connect remembered 30s (APCu when available, else per process plus a temp-file marker per DSN; N-L14, R3-L39). There is no cache-pool fallback anymore.
- **`Service/Session/Sw6OidcSessionRegistry`** (`sw6oidc_session`, DBAL) — which local sessions an OIDC login created (`Sw6OidcSession`: id, provider, `sub`, optional `sid`, user type/id, `sessionKey`, sales channel, id_token, IdP access/refresh token, created/expires). `sessionKey` and tokens are encrypted (purposes `sw6oidc_session.<column>`), looked up by `session_key_hash`; rows written under another `APP_SECRET` are skipped. Single-query lookups (N-L20): `register()`, `resolve(providerId, sub)`, `resolveBySid()`, `findBySessionKey()`, `findForUser(userType, userId, id)`, `activate(id, sessionKey)`, `remove()`, `removeAllForUser()`, `get()`, `prune()`. Liveness follows core's session state (R3-H5): admin entries live while the admin has an unexpired `refresh_token`, customer entries while their `sales_channel_api_context` in that channel was used within `shopware.api.store.context_lifetime`; `expires_at` is only a 90-day hard bound (`HARD_TTL_SECONDS`), pending admin entries 600s. Rows go with their provider (FK `ON DELETE CASCADE`, R3-L34). The id_token is stored only here (N-L10).
- **`sessionKey`** — Storefront: the context token minted by the login (`OidcCallbackController`). Admin: the callback registers a `pending:<random>` entry (600s) with id_token and IdP tokens and passes its id in the nonce; `exchangeNonce()` calls `activate()` with the access token's jti (full lifetime). `sid` only from the verified id_token. Passkey logins are not registered (no IdP session).
- **Login-session handle** — the registry id returned to the Administration as `sw6oidc_login_session` and sent back at logout; survives token refreshes (unlike the jti).
- **`LogoutContextStore`** — admin-only fallback: provider id of the admin's last login (30 days, last login wins), no id_token.
- **`Service/Session/Sw6OidcSessionDestructionService`** — customer: exact (`SalesChannelContextPersister::delete()` of the context token); if core rotated that token meanwhile (password change), all of the customer's sessions end instead (R3-L30). Admin: can't be targeted (stateless JWTs, rotating refresh tokens), so **all** of that admin's sessions end: `RefreshTokenRepository::revokeRefreshTokensForUser()` + bumping `user.last_updated_password_at` (core's bearer validator rejects older tokens; password untouched).
- **Other stores on `cache.app`** (non-security-critical or self-healing): JWKS cache + circuit breakers (per scope), CSP host list, health result (30s). `LockoutConfirmationStore` and `IssuerChangeConfirmationStore` use `AtomicCacheInterface` (5 min, keyed by provider + confirming admin, R3-M22).

## Architecture — Session activity log

- **Schema** — `sw6oidc_session_activity` (`Core/Content/SessionActivity/`): one row per login — provider (FK, `SET NULL`), polymorphic `user_type`/`user_id`, `sub`/`sid`, `login_method` (`oidc`/`passkey`), `ip_address`, `user_agent`, `logged_in_at`, `logged_out_at`, `logout_reason` (`logout`/`backchannel`/`frontchannel`/`forced`). **Every field `WriteProtected(system)`** (N-M8); `sub`/`sid` (`sid` only as `sha256:<hex>`, R3-L40), `session_key_hash` (sha256 of context token / first jti) and `registry_session_id` are internal, not `ApiAware` (N-M5).
- **`Subscriber/SessionActivityWriteGuardSubscriber`** — refuses deletes outside system scope (`SW6OIDC_AUDIT_LOG_READ_ONLY`); retention and account deletion remove rows via DBAL.
- **`Service/Session/Sw6OidcSessionActivityRecorder`** — `recordLogin()` from all four login-completing paths (also records a `NodeHeartbeat`), `recordLogout()` (by registry id, else session-key hash, optionally the account's newest open row), `recordLogoutOfAllSessions()`. IPs stored truncated (IPv4 /24, IPv6 /64) with `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP=1` (N-L12). Every method swallows and logs its own errors. A logout finds its row with one indexed OR query; ending all sessions closes rows in batches (R3-L31).
- **`Controller/Api/SessionActivityController`** — `GET /api/_action/sw6oidc/session-activity/settings` (`sw6oidc_session_activity:read`; session lifetimes per account type so the list labels older open rows as expired, F-N3) and `POST …/{activityId}/force-logout` (`_acl: sw6oidc_session_activity:force_logout`). A customer session still in the registry is destroyed exactly; otherwise (passkey logins, all admins) all sessions of the account end, registry entries are removed and open rows closed as `forced`. Returns `{alreadyLoggedOut, endedAllSessions}`.
- **Retention / housekeeping** — `ScheduledTask/SessionActivityCleanupTask` (daily, `sw6oidc.session_activity_cleanup`) + handler: activity rows older than `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` (default 90, 0 = keep) deleted in batches of 1000, plus expired registry entries, one-time tokens and node heartbeats older than a day. The `scheduled_task` row is created by core's `PluginLifecycleSubscriber` on install/update (or `bin/console scheduled-task:register`).
- **Admin UI** — `module/sw6oidc-sessions/` (`sw6oidc-sessions-list`): newest first, "only active" switch, owner names, load errors shown, force logout via `sw-confirm-modal` (text matches what ends).

## Architecture — Health checks & alerting

- **Schema** — `sw6oidc_provider` admin settings `health_alert_webhook_url` (`Sw6OidcEncryptedField`, write-only), `health_alert_failure_threshold` (0 = off), `health_alert_notify_on_recovery`, and task-owned state `health_alert_consecutive_failures`/`_last_status`/`_last_checked_at`/`_first_failure_at`/`_last_notified_at` (`WriteProtected`, written via DBAL). Excluded from config export. The write guard decrypts and SSRF-checks the webhook URL.
- **`Service/Health/ProviderConfigInspector`** — local completeness check (endpoints, issuer, client id, secret present and decryptable for confidential clients). No HTTP.
- **`Service/Health/ProviderReachabilityChecker`** — JWKS with non-empty `keys`, else discovery doc with `issuer`; SSRF re-check, `sw6oidc.http_client`.
- **`Service/Health/HealthAlertState`** — pure transition function (once-per-outage alert, optional recovery notice). `ProviderHealthMonitor` marks an alert sent only when the webhook accepted it.
- **`Service/Health/WebhookNotifier`** — JSON POST on `sw6oidc.http_client`, SSRF re-check, never throws; failures log class/code only (N-L8).
- **`ScheduledTask/HealthCheckAlertTask`** (`sw6oidc.health_check_alert`, 300s) + handler → `ProviderHealthMonitor::run()` over monitored providers (threshold > 0 and a webhook). No node heartbeat here: the worker isn't a web node (R3-L32).
- **`Service/Health/NodeHeartbeat`** (`sw6oidc_node_heartbeat`, hostname + last seen) and **`Service/Health/InfrastructureInspector`** — `inspect()` → `{atomicStore, nodesSeen, warnings}` with `redis_dsn_unusable` (DSN set but not in use) and `multi_node_without_redis` (> 1 node in 15 min without Redis: one-time tokens stay correct in the DB, but the rate limiter and JWKS cache are per node unless the cache pools are shared). Warnings never fail the health check.
- **`Controller/HealthCheckController`** — `GET /sw6oidc/health` (storefront scope, unauthenticated, no outbound HTTP; records the node heartbeat, throttled per process). Without `SW6OIDC_HEALTH_TOKEN` the answer is `{status}` only; with the token, counts and warning codes too (R3-L36). `ok` 200, `degraded` 200 (some provider incomplete or its monitored probe failed, but SSO still works), `down` **503** (no usable provider), `unconfigured` 200. Only monitored providers count their probe; results older than 900s are `unknown` (N-M14). Result cached 30s. With `SW6OIDC_HEALTH_TOKEN` set, the `X-Sw6oidc-Health-Token` header is required (401 otherwise).
- **`Controller/Api/OidcDiagnosticsController`** — `POST /api/_action/sw6oidc/provider/{id}/diagnostics` (`sw6oidc_provider:read`): config problems + live probe + alert state (`webhookConfigured` flag only) + infrastructure warnings, shown in the Administration.

## Architecture — Claims-based access control

- **Schema** — `sw6oidc_access_control_rule` (cascade delete with the provider): `claim_key`, `operator` (strict `Choice` on `Sw6OidcAccessControlRuleDefinition::OPERATORS`: `eq`/`neq`/`contains`/`not_contains`/`exists`/`not_exists`/`ends_with`/`email_domain`, N-L13), nullable `value`/`error_message`, `sort_order`.
- **`Service/Security/Sw6OidcAccessControlEvaluator`** — rules ordered by `sortOrder`, AND-combined, first failure throws `AccessControlDeniedException`. No rules = allow. Works on the **flattened** claims; a claim's *values* are its members (numeric children's scalars `groups.0`, … plus non-numeric child names, Zitadel `roles.Admins.orgId` → `admins`) when it has any, else its scalar:
  - `eq` — any value equals; `neq` — claim present and no value equals;
  - `contains` — a member equals; on a scalar, an exact whitespace/comma-separated **token** equals (never a substring, N-M11); `not_contains` — claim present and `contains` false;
  - `ends_with` — any value ends with the suffix; `email_domain` — any value is an email whose domain is exactly the expected one (leading `@` ignored);
  - `exists`/`not_exists` — the key or any child key.
  - Negative operators (`NEGATIVE_OPERATORS`) **deny on a missing claim** (group overage / ungranted scope can't skip a deny rule, N-M10). Case-insensitive, trimmed; booleans/`"true"`/`1` compare equal. Unknown operator fails closed. `matches()` is public for tests.
- **Hook** — `OidcCallbackProcessor::process()`, after `flatten()`, before `AttributeMapper::map()`. The live login test evaluates rules too but only reports them (status `warning`).
- **Surfacing the message** — `getDisplayMessage()` (plain text, 500 chars) or null. Storefront flashes it (fallback `sw6oidc.login.accessDenied`). Admin callback never puts free text into the URL: `AdminLoginErrorTicketStore` (`AtomicCacheInterface`, 60s, single-use) + `sw6oidc_error=access_denied&sw6oidc_error_ticket=…`, redeemed via `GET /api/sw6oidc/admin/login-error/{ticket}` (anonymous, `redeem` failure budget).
- **Config transfer** — rules travel with the provider and are only replaced on `--overwrite` when the file carries them.

## Architecture — Identity & account linking

Accounts are bound to the IdP **subject**, never looked up by the email claim alone (C2, H1).

- **`sw6oidc_user_provider`** — `provider_id`, `issuer` + `issuer_hash` (sha256), `sub` (both `utf8mb4_bin`), `binding_scope` (the sales channel of a channel-bound customer, else 16 zero bytes = global), polymorphic `user_type`/`user_id`; unique per account and unique `(provider_id, user_type, issuer_hash, sub, binding_scope)` (R3-M9, R3-M14). Every field is `WriteProtected(system)`; inserts and deletes outside system scope are refused by `TrustEntityWriteGuardSubscriber` (R3-H3). Legacy rows have `sub = NULL`.
- **`ExternalIdentity`** — provider id, `iss` + `sub`, email, `email_verified` (from `OidcCallbackResult::identity()`).
- **`Service/Provisioning/IdentityResolver::resolve(userType, provider, identity, emailMatchedUserId, emailMatchIsPrivileged)`** — shared by customer and admin provisioning:
  0. `require_email_verified` (provider, default **on**) and no `email_verified` → `EmailNotVerifiedException` (applies to every login);
  1. account bound to this provider + issuer + subject (in the Storefront sales channel's scope first, then globally) → it;
  2. email-matched account with a **legacy** binding to this provider → subject backfilled (verified email only and never for a privileged account — every admin — else `AccountLinkingRequiredException`, R3-M10); bound to another provider → `ProviderMismatchException`; bound to another subject of this provider → `AccountLinkingRequiredException`;
  3. unbound email-matched account → linked only with `link_existing_accounts` (default **off**), a verified email and **never a superadmin**; else `AccountLinkingRequiredException`;
  4. nothing → null, the caller may JIT-create.
- **`linkExplicitly(userType, userId, identity)`** — "Connect SSO": the owner proved the account (session + step-up) and the IdP identity (this round trip), so no email match is needed; the only way to bind a superadmin. `SubjectAlreadyLinkedException` / `ProviderMismatchException` on conflicts.
  - Storefront: `POST /sw6oidc/link` (`_loginRequired`, provider buttons on the account profile page via `sw6oidc_storefront_account_sso()`) needs a freshly authenticated browser session (`SessionAuthenticationClock`, else `/sw6oidc/reauth?target=profile`, R3-H6); `OidcCallbackController::completeLink()` binds only if the same customer is still logged in, in the customer's channel scope. Every explicit link dispatches `AccountSsoLinkedEvent` (Flow Builder trigger `sw6oidc.account.sso_linked`).
  - Admin: `POST /api/sw6oidc/admin/link/start` (auth required, **`user-verified` token required**) returns `{authorizeUrl}`; the callback's `completeLink()` binds and redirects to `#/sw/profile/index/general?sw6oidc_linked=1`. UI: `component/sw6oidc-connect-sso` on the own profile.
- **`UserProviderBindingService`** — the only writer (always in system scope): `getBinding()`, `findBindingBySubject()`/`findUserIdBySubject(userType, identity, ctx, ?salesChannelId)`, `bind(…, ?bindingScope)` (unique-key race on concurrent first logins: re-reads and accepts only the identical binding, M21), `backfillSubject()`, `unbind()`, `issuerHash()`.
- **Issuer change** (R3-M9): bindings no longer match after a provider's issuer changes. With bound accounts the save needs a superadmin's decision (`POST /api/_action/sw6oidc/provider/{id}/confirm-issuer-change` `{rebind}`, `user-verified`): re-bind them to the new issuer after commit, or leave them disconnected (CLI: disconnected).
- Callback error codes: admin `sw6oidc_error=link_required|email_not_verified|provider_mismatch`; Storefront flash messages. Account-policy denials are not counted by the rate limiter.

## Architecture — Step-up (fresh re-authentication, Administration)

- **`Service/AdminAuth/StepUpService`** — the one "fresh authentication" primitive, for everything core protects with password re-confirmation (`user-verified` tokens) plus "Connect SSO" and admin passkey registration:
  - OIDC: round trip to the admin's **own bound** provider with `prompt=login` (flow purpose `step_up`, `expectedUserId`); `completeOidc()` requires `auth_time` after the round trip started (`AuthTimeValidator`, 60s leeway) and the subject of the admin's binding, returns a one-time nonce (120s).
  - Passkey: assertion with one of the admin's own passkeys (`allowCredentials` = own keys), UV required.
  - Result: `AdminTokenIssuer::issue(..., stepUp: true)` → access-only token with `user-verified`, ≤ 5 min, no refresh token.
- **`Controller/Api/StepUpController`** (auth required, own user only) — `GET /api/sw6oidc/admin/step-up/methods`, `POST …/oidc/start`, `POST …/token` (redeems the popup's nonce), `POST …/passkey/options`, `POST …/passkey/verify`; failures counted per admin and address.
- The OIDC popup's callback page (`completeStepUp()`) posts `{type: 'sw6oidc-step-up', nonce|error}` to the opener restricted to the Administration origin (nonce'd inline script, strict CSP) and closes.
- **Administration** — `extension/sw-verify-user-modal` adds "confirm with SSO / passkey" to core's password modal and installs the returned token exactly like core's password check. `UserVerifiedScope::isPresent($request)` checks the scope server-side.
- The former `verify-session` endpoint and the `ssoSettingsService.isSso()` decorator (which turned OIDC sessions into password-less "native SSO" sessions) are **gone** (H2, F-C1). The SSO user detail override is a narrow block extension, not a template copy (F-N5).

## Architecture — Passkey (WebAuthn) flow

Independent of OIDC; uses `web-auth/webauthn-lib` **^5.3** (no repository contract: the plugin looks up and persists `CredentialRecord`s itself). All ceremony endpoints answer **404** while passkeys are disabled for that side (`passkeyEnabledAdmin`, `passkeyEnabledCustomer` per sales channel).

- **`WebauthnCeremonyFactory`** — single seam: RP entity, algorithms **ES256, EdDSA, RS256**, `residentKey=required`, **user verification required** for registration and login (H6), attestation `'none'`. Validators only accept the **exact origins** pinned into the ceremony (no subdomains, N-M1). All JSON via the library's serializer; `serializeOptions()` skips nulls.
- **`PasskeyRelyingPartyResolver`** → `PasskeyRelyingParty` (RP ID, name, exact origins) from configuration, **never the Host header** (M17): Administration = origin of `APP_URL`, RP ID its host unless `passkeyRpIdAdmin` (global); Storefront = origins of the current sales channel's domains (only those under the RP ID), RP ID the current domain's host unless `passkeyRpId` (per sales channel). Both are validated on save (`PasskeyRpIdConfigValidator`, R3-M8).
- **Write protection** (R3-H2): every credential field but `nickname` is `WriteProtected(system)`; inserts outside system scope are refused (`TrustEntityWriteGuardSubscriber`). Deleting stays possible (recovery grid).
- **Ceremony purpose** (R3-M7): login ceremonies store a purpose (`storefront-login:<channel>`, `admin-login`, `admin-stepup:<user>`) and only complete for it.
- **`PasskeyCredentialRepository`** — `findOneByCredentialId()` / dedup via `credential_id_hash` (sha256 of the base64 id; column `credential_id` widened to 1400 chars for ids up to 1023 bytes, L7), `findAllForUserHandle(handle, includeDisabled)`, `saveNewCredentialRecord()`, `updateAfterAssertion()`, `disable()`, `findAllForOwner()`, `existsForUserType()`, `deleteOwnedByUser()` (ownership enforced). `public_key` holds normalized `CredentialRecord` JSON; 4.x rows deserialize unchanged.
- **`PasskeyRegistrationService::buildCreationOptions()`** / **`PasskeyAuthenticationService::buildRequestOptions()`** — challenge, options (userHandle = `sha256("{userType}:{userId}")`), raw inputs + pinned RP cached 300s in `AtomicCacheInterface`. `verifyAndPersist(..., userType, userId)` completes only for the account that started the ceremony (N-M2) and dispatches `PasskeyRegisteredEvent`.
- **Clone detection** — a signature counter going backwards disables the credential (`disabled_at`) with a warning; disabled credentials can't log in, are still listed in `excludeCredentials` (N-L16).
- **Admin** (`PasskeyAdminController`, `/api/sw6oidc/admin/passkey/*`): registration needs a **`user-verified`** token (H7); login is **always usernameless** (`allowCredentials=[]`, nothing reveals which accounts exist, M6); the inactivity modal passes `expectedUsername` and an assertion by another account is refused (F-H6). `my-credentials`/`delete` work even while disabled.
- **Deleting a passkey ends its sessions** (R3-M6): activity rows store the logging-in key's `passkey_credential_hash`; `PasskeyDeletionSubscriber` (any delete path) calls `PasskeySessionTerminator` after commit: customers lose exactly those contexts (matched by `SHA2(token)`), admins all sessions (their tokens can't be targeted); the admin response says `forceLogout`.
- **Storefront** (`PasskeyController`, `/sw6oidc/passkey/*`; `AccountPasskeyController` `GET /account/passkey`, `POST /account/passkey/delete/{credentialId}`): usernameless login; registration needs a freshly authenticated *browser session* (`SessionAuthenticationClock`: PHP session, bound to the customer, set by every `CustomerLoginEvent` and by the reauth flow; 600 s) — not `customer.lastLogin`, because core shares one context token between all logins of a customer (R3-M5). Else `GET /sw6oidc/reauth`: SSO-bound customers make a `reauth` round trip (`prompt=login`, `auth_time` and bound subject checked), others are logged out and asked to log in again (H7).
- Public error responses carry a fixed code + correlation reference (`PublicError`), never exception text (M7).
- **Limits** — at most `MAX_CREDENTIALS_PER_ACCOUNT` (20) passkeys per account (409 `passkey_limit_reached`); Storefront registration options consume a budget per customer (R3-L13). The four Storefront ceremony POSTs refuse cross-origin requests (`Sec-Fetch-Site` / `Origin`, login CSRF, R3-L14). The signature counter is written compare-and-set (`UPDATE … WHERE sign_count < :new`), so concurrent assertions can't lower it (R3-L15). Non-user API sources get 403 on the admin endpoints; malformed credential ids are "not found" (R3-L16). Browsers' `transports` and `clientExtensionResults` are sent and stored (R3-L17). Storefront origins come from the domains in the sales-channel context (R3-L19).

## Architecture — Provisioning & mapping

- **`AttributeMapper::map()`** — 22 attribute types (`Sw6OidcAttributeMappingDefinition::TYPE_*`: email, username, firstname, lastname, birthday, gender, phone, locale, zoneinfo, picture, 6 billing_*, 6 shipping_*). The email is punycode-encoded like core's (`EmailIdnConverter`, R3-L20); every value is cut to its column limit (`MappedProfile::truncatedToFieldLimits()`, R3-L21). Only identity fields have default claim keys; address fields stay unmapped until configured. Missing/invalid email → `MissingEmailClaimException`. Gender → `salutation` via `GenderMapper`. Dispatches `AttributeMappingCompletedEvent`, email re-validated afterwards.
- **`AttributeTransformer::apply()`** — optional per-mapping transform (`concat`, `split`, `prefix`, `regex_replace`; caps 4096 bytes), applied on every login even when the claim is missing. A failure on a normal field logs and passes through; on **email/username it fails the login** (`AttributeTransformFailedException`, N-L7). Invalid `regex_replace` patterns are rejected at save time by `Subscriber/AttributeMappingWriteGuardSubscriber` (`SW6OIDC_TRANSFORM_PATTERN_INVALID`, F-N16). `transform_function` is a strict `Choice`.
- **`CustomerProvisioningService::findOrCreateCustomer(provider, profile, identity)`** — email lookup respects Shopware's bind-customers-to-sales-channel setting (`CustomerSalesChannelBinding`), then `IdentityResolver::resolve()`. Existing → `syncExisting()`. None and `auto_create_customer` off → `CustomerProvisioningDeniedException`. Create: customer group via `GroupMappingResolver`, generated number, random unused password, no `defaultPaymentMethodId`; billing address from claims, else placeholders `-` (no zipcode placeholder) flagged with `customFields.sw6oidc_placeholder_address` (M16); optional distinct shipping address; birthdate only as strict `Y-m-d` between 1900 and today, else skipped (M9); never the email as a name (local part instead, L9). Dispatches `CustomerBeforeCreateEvent`, binds, then core's **`CustomerRegisterEvent`** (Flow Builder) and `CustomerAfterCreateEvent`. Customers are then logged in **by id** through core's `AccountService::loginById()` after `CustomerSalesChannelBinding::assertCanLogIn()` (no guests, right channel; R4-L5), never re-resolved by email (M8). The email lookup prefers the newest active account but never skips an inactive one (a deactivated customer must not get a fresh account, R3-L26). Sync writes only changed fields and addresses (R3-L29).
- **Sync-on-SSO** — `syncExisting()` / `AdminProvisioningService::syncProfile()`/`syncRole()`, gated per toggle (`sync_customer_profile_on_sso`, `sync_customer_address_on_sso`, `sync_customer_group_on_sso`, `sync_admin_profile_on_sso`, `sync_admin_role_on_sso`). Profile/address/group: partial updates only (unmapped claim or unresolved group = left alone); address sync updates existing default addresses in place, never creates one.
- **`AdminProvisioningService::findOrCreateAdmin(provider, profile, identity)`** — `IdentityResolver::resolve()` (superadmins never linked by email). None and `auto_create_admin` off → `AdminProvisioningDeniedException::autoCreateDisabled()`. Creation needs a resolved ACL role (mapping, else `default_acl_role_id`) or a superadmin grant, else `noRoleResolved()`. Username from mapped username or email local part, deduplicated, retried on concurrent-login unique-key races; never the email as a name. `AdminBeforeCreateEvent` listener changes that escalate (superadmin, roles) are logged, and the email is forced back to the verified claim (N-L17).
- **Role sync (`syncRole`, H3, R3-M11)** — superadmin group match (two gates: `allow_superadmin_group_mapping` + explicit `superadmin` mapping row) grants superadmin; otherwise every mapped role is added and roles role sync granted earlier (`sw6oidc_managed_acl_role`, `AdminRoleStore`) that no group grants any more are removed. Roles granted by hand are never touched; provider defaults apply on create only. Superadmin is revoked only with `revoke_superadmin_on_sso` (default off) — also when nothing resolves — and **never from the last active superadmin** (checked with the rows locked).
- **Profile sync** — first/last name, locale (exact `Locale.code`), timezone (`TimeZoneValidator`), avatar: `AvatarFetcher` downloads the `picture` URL through `sw6oidc.http_client` (SSRF-guarded, raster only, ≤ 2 MB, ≤ 3 IP-checked redirects); skipped when the URL's sha256 equals `customFields.sw6oidc_avatar_url_hash` and the avatar still exists (M19); failures never break login.
- **`GroupMappingResolver`** — `resolveAclRoleIds()` (every match, no default), `resolveCustomerGroupId(…, withDefault)` (first by `sort_order`; the default only on create), `matchesSuperadminGroup()` (no fallback). Case-insensitive.
- **JIT safety** — create + bind run in one transaction; a unique violation re-resolves and uses the winner's account (R3-M12). JIT customers follow core's bound-sales-channel rule (R3-M13) and are bound in that channel's scope (R3-M14). Placeholder addresses are sent to the address form before checkout and unflagged on real values (`PlaceholderAddressSubscriber`, R3-M16). Mapping rows loaded once per request per provider (L8); resettable (`kernel.reset`, M20), as is `CountryResolver`.
- **Account cleanup** — `Subscriber/UserProviderCleanupSubscriber`: on `user`/`customer` **deleted** removes binding, passkeys, registry entries and activity rows (no FK on polymorphic ids); on **deactivation** ends every session of the account (M15).

## Directory / component reference

**`Service/Oidc/`**
- `OidcCallbackProcessor` / `OidcCallbackResult` — shared post-redirect pipeline (see above).
- `AuthorizationRequestBuilder` — authorize-URL construction (with optional purpose, expected user, extra params).
- `ClaimsMerger` — id_token/userinfo merge rules, `requestsOpenIdScope()`.
- `TokenExchangeService`, `UserInfoService`.
- `ClaimsNormalizer` — `flatten()`, `normalizeGroups()`, `decodeGroups()`, `isBase64Claim()`.
- `OidcDiscoveryService`, `OidcConnectionTestService`, `OidcLiveLoginTestService` (safe subset of the pipeline, needs `sw6oidc_provider:update`, stores claim keys only, previews access control), `TestResultTranslator`.
- `RpInitiatedLogoutService`, `PostLogoutState`, `LogoutContext`/`LogoutContextStore` — logout (see above).

**`Service/AdminAuth/`**
- `AdminOidcGrant`, `AdminAuthorizationServerFactory`, `AdminTokenIssuer`, `AdminLoginNonceService`/`AdminLoginNonce` — admin OIDC ↔ League OAuth2 bridge.
- `StepUpService` — fresh re-authentication.
- `PasswordLoginGuardUserRepository` — decorates core's OAuth `UserRepository` (password-login enforcement).
- `AdminLoginErrorTicketStore` — one-time error-message hand-off.

**`Service/Passkey/`** — `WebauthnCeremonyFactory`, `PasskeyRelyingParty`/`PasskeyRelyingPartyResolver`, `PasskeyCredentialRepository`, `PasskeyRegistrationService`, `PasskeyAuthenticationService`, `PasskeySessionTerminator`, `PasskeyConfig` (enable toggles, `passkeyRpName`, `passkeyRpId`, `passkeyRpIdAdmin`).

**`Service/Provisioning/`** — `IdentityResolver`, `ExternalIdentity`, `UserProviderBindingService`, `AttributeMapper`, `AttributeTransformer`, `CustomerProvisioningService`, `AdminProvisioningService`, `AvatarFetcher`, `GroupMappingResolver`, `CountryResolver`, `CustomerSalesChannelBinding`, `GenderMapper`, `TimeZoneValidator`, `MappedProfile`/`AddressProfile` DTOs; exceptions `AccountLinkingRequiredException`, `EmailNotVerifiedException`, `ProviderMismatchException`, `SubjectAlreadyLinkedException`, `AttributeTransformFailedException`, `MissingEmailClaimException`, `*ProvisioningDeniedException`.

**`Service/Provider/ProviderResolver`** — `getActiveById(id, loginType)`, `findByIssuer()`, `getActiveProviders()`, `getVisibleProviders()`, `resolveDefault()`.

**`Service/Security/`** — `OidcSecurityHelper`, `AuthorizationFlowContext`, `BrowserBinding`, `RelayStateValidator`, `LoginType` (enum `admin`/`customer`, L11), `Sw6OidcEncryptor`, `SsrfUrlValidator`, `PasswordLoginPolicy`, `SsoOnlyInvariant`, `LockoutConfirmationStore`, `IssuerChangeConfirmationStore`, `PasswordSessionRevoker` (+ `Message\PasswordSessionRevocationMessage`), `UserVerifiedScope`, `PublicError`, `Sw6OidcCspHostCollector`, `Sw6OidcAccessControlEvaluator`, `Sw6OidcRateLimiter`; exceptions `ClientSecretUnavailableException`, `PasswordLoginDisabledException`, `InvalidStateException`, `UnknownStateException`, `AccessControlDeniedException`.

**`Service/Session/`** — `SessionAuthenticationClock`, `Sw6OidcSession`, `Sw6OidcSessionRegistry`, `Sw6OidcSessionDestructionService`, `Sw6OidcIdpLogoutHandler`, `Sw6OidcSessionActivityRecorder`.

**`Service/Cache/`** — `AtomicCacheInterface`, `RedisAtomicCache` (always wired, runtime backend selection), `DatabaseAtomicCache`, `RedisConnectionFactory`.

**`Service/Health/`** — `ProviderConfigInspector`, `ProviderReachabilityChecker`/`ReachabilityResult`, `HealthAlertState`, `ProviderHealthMonitor`, `WebhookNotifier`, `NodeHeartbeat`, `InfrastructureInspector`.

**`Service/Logging/`** — `ConfigurableLevelHandler`, `SensitiveDataProcessor` (see Logging). **`Service/Http/`** — `OidcHttpClient`, `Sw6OidcHttpClientFactory`. **`Service/Jwt/`** — `JwtVerifier`, `JwtPayloadReader` (unverified decode for tokens verified elsewhere). **`Service/Config/`** — `OidcConfigTransfer`, `ImportResult`. **`Console/`** — export/import commands. **`ScheduledTask/`** — `SessionActivityCleanupTask`, `HealthCheckAlertTask` + handlers. **`Event/`** — see Extension points.

**`Storefront/Controller/`**
- `SendAuthorizationRequestController` — `GET /sw6oidc/login`, `POST /sw6oidc/link` (login required), `GET /sw6oidc/reauth` (login required).
- `OidcCallbackController` (`GET /sw6oidc/callback`), `PasskeyController` (`/sw6oidc/passkey/{registration,login}-{options,verify}`), `AccountPasskeyController`.

**`Storefront/Service/`** — `OidcLogoutRoute` (decorates `LogoutRoute`), `PendingLogoutRedirect`, `PasswordLoginGuardLoginRoute` / `PasswordLoginGuardRegisterRoute` / `PasswordLoginGuardRegisterConfirmRoute` (decorate core `LoginRoute`/`RegisterRoute`/`RegisterConfirmRoute`). **`Storefront/EventSubscriber/`** — `CustomerLogoutSubscriber`, `PasswordLoginDisabledExceptionSubscriber` (Storefront: flash message on the login page; Store API keeps the 403 JSON).

**`Controller/Oidc/`** — `BackChannelLogoutController`, `FrontChannelLogoutController`, `PostLogoutController`. **`Controller/HealthCheckController`** — `GET /sw6oidc/health`.

**`Controller/Api/`**
- `OidcAdminAuthController` — `login-options`, `login`, `callback`, `token`, `login-error/{ticket}` (anonymous) and `link/start`, `logout` (auth required) under `/api/sw6oidc/admin/*`.
- `StepUpController` — `/api/sw6oidc/admin/step-up/*`.
- `PasskeyAdminController` — `/api/sw6oidc/admin/passkey/*`.
- `OidcProviderAdminController` — `GET /api/_action/sw6oidc/provider/form-context` (`sw6oidc_provider:read`: webhook configured/stored state, storefront post-logout URL, F-N6/F-N15), `POST …/discover`, `…/test-connection`, `…/{id}/test` (all `sw6oidc_provider:update`), `GET /api/sw6oidc/provider/test-callback` (anonymous live-test popup return, own nonce'd CSP).
- `ProviderLockoutConfirmationController` — `POST /api/_action/sw6oidc/provider/{providerId}/confirm-lockout` (`sw6oidc_provider:update`).
- `OidcUserProviderAdminController` — `POST /api/_action/sw6oidc/user-provider/info` / `…/unlink`, gated per request by core `user:read|update` / `customer:read|update` of the given userType (an admin may always read their own binding); unlink in system scope.
- `OidcDiagnosticsController`, `SessionActivityController` — see above.

**`Subscriber/`**
- `Sw6OidcProviderWriteGuardSubscriber` — provider save-time validation (SSRF, redirect URLs, client secret rules, SSO-only invariant, issuer change, password-session revocation via the message queue).
- `ProviderTrustGuardSubscriber` — trust-relevant provider fields, privileged role mappings and identity mappings/access rules of admin providers need a superadmin; audit log (R3-H4).
- `TrustEntityWriteGuardSubscriber` — passkey credentials and bindings are written by the plugin only (R3-H2, R3-H3).
- `AdminLockoutGuardSubscriber` — refuses deleting/deactivating the last admin able to log in via SSO while SSO-only mode is on (`SW6OIDC_LAST_SSO_ADMIN`); asks `SsoOnlyInvariant`.
- `AdminPasswordLoginGuardSubscriber` — friendly 403 on `/api/oauth/token` for password grants and user-access-key `client_credentials` (enforcement for user access keys; for passwords the real enforcement is `PasswordLoginGuardUserRepository`).
- `AttributeMappingWriteGuardSubscriber`, `SessionActivityWriteGuardSubscriber`, `ProviderSecretPayloadScrubber`, `BrowserBindingCookieSubscriber`, `BusinessEventSubscriber` (registers `PasskeyRegisteredEvent` as Flow Builder trigger), `UserProviderCleanupSubscriber`, `Sw6OidcCspSubscriber`.

**`Migration/`**
- `Migration1730000001CreateOidcSchema` — creates the initial 5 tables; `updateDestructive()` is a no-op.
- `Migration1758000001AddProviderTestStatus` — adds `sw6oidc_provider.last_test_status`/`last_test_at`.
- `Migration1789383427AddSuperadminGroupMapping` — adds `sw6oidc_provider.allow_superadmin_group_mapping`.
- `Migration1789390512AddLastTestClaims` — adds `sw6oidc_provider.last_test_claims` (JSON; claim keys of the last live test, for the attribute-mapping picker).
- `Migration1789470000AddUserProviderUpdatedAt` — adds the missing `sw6oidc_user_provider.updated_at`.
- `Migration1790685361EncryptProviderClientSecrets` — widens `client_secret` to 2048 and encrypts existing plaintext rows (v1; needs `APP_SECRET`).
- `Migration1790686535DropAttributeMappingSyncOnSso` — destructive step drops `sw6oidc_attribute_mapping.sync_on_sso`.
- `Migration1790800001CreateAccessControlRuleSchema` — creates `sw6oidc_access_control_rule`.
- `Migration1790800002AddProviderPostLogoutUrl` — adds `sw6oidc_provider.post_logout_url`.
- `Migration1790800003CreateSessionActivitySchema` — creates `sw6oidc_session_activity`.
- `Migration1790800004AddProviderHealthAlerting` — adds the `sw6oidc_provider.health_alert_*` columns.
- `Migration1790800005AddUserProviderSubject` — adds `sw6oidc_user_provider.issuer`/`sub` + unique `(provider_id, user_type, sub)`, and `sw6oidc_provider.require_email_verified` (default 1) / `link_existing_accounts` (default 0).
- `Migration1790800006CreateStateTables` — creates `sw6oidc_session`, `sw6oidc_one_time_token`, `sw6oidc_node_heartbeat`.
- `Migration1790800007PasskeyCredentialHardening` — adds `disabled_at`, `credential_id_hash` (backfilled, unique; replaces the `credential_id` unique key), widens `credential_id` to 1400, indexes `user_handle`.
- `Migration1790800008AddProviderFrontchannelAdminLogout` — adds `sw6oidc_provider.frontchannel_admin_logout` (default 0).
- `Migration1790800009AddProviderRevokeSuperadminOnSso` — adds `sw6oidc_provider.revoke_superadmin_on_sso` (default 0).
- `Migration1790800010ReencryptSecrets` — re-encrypts `client_secret`/`health_alert_webhook_url` from v1 to v2 envelopes (idempotent; undecryptable values left alone; skipped without `APP_SECRET`).
- `Migration1790800011AddProviderBase64Claims` — adds `sw6oidc_provider.base64_claims` (JSON list); `claim_encoding = base64` rows get `["*"]`.
- `Migration1790800012DropProviderButtonColumns` — destructive step drops the never-read `button_label`/`button_color`.
- `Migration1790800013MakeClientSecretOptional` — `client_secret` nullable; empty public-client placeholders become NULL.
- `Migration1790800014AddSessionActivityPasskeyCredential` — `sw6oidc_session_activity.passkey_credential_hash`.
- `Migration1790800015SplitPasskeyRpId` — new `passkeyRpIdAdmin`, seeded from a fitting `passkeyRpId`.
- `Migration1790800016AddProviderLogoutStyle` — `sw6oidc_provider.logout_style`.
- `Migration1790800017BindingIdentityKey` — binding `issuer_hash`, `binding_scope`, binary `sub`/`issuer`, new unique key.
- `Migration1790800018CreateManagedAclRole` — `sw6oidc_managed_acl_role`, seeded.
- `Migration1790800019SessionProviderCascadeAndHashedSid` — orphans removed, then `sw6oidc_session.provider_id` FK `ON DELETE CASCADE`; activity `sid` stored as `sha256:<hex>`.
- `Migration1790800020DropProviderClaimEncoding` — destructive step drops the unread `claim_encoding`.
- `Migration1790800021AddProviderClientAuthMethods` — `sw6oidc_provider.token_endpoint_auth_method`/`revocation_endpoint_auth_method` (default `client_secret_basic`).

**`Twig/`**
- `AdminEntrypointsExtension` — `sw6oidc_admin_scripts()`/`sw6oidc_admin_styles()`, reading the plugin's Vite `entrypoints.json` directly (parse failures degrade gracefully). Forces the plugin's admin JS onto the pre-auth login screen.
- `StorefrontLoginOptionsExtension` + `StorefrontLoginOptionsRuntime` (lazy `twig.runtime`, memoised per request, R3-L46/L47) — `sw6oidc_storefront_sso_providers(context)`, `sw6oidc_storefront_passkey_available(context)`, `sw6oidc_storefront_passkey_enabled(context)` (account sidebar link), `sw6oidc_storefront_password_login_disabled(context)`, `sw6oidc_storefront_account_sso(context)` (profile "Connect SSO" card).

**`Resources/app/administration/src/`**
- `service/sw6oidc-api.service.js` (`Sw6oidcApiService`) — the plugin's Admin API client on Shopware's own HTTP client (API base path, token refresh; `anonymous: true` for pre-auth calls). No raw `fetch()` for API calls (F-H4/F-N2).
- `acl/index.js` — privilege mappings for `sw6oidc_provider` (viewer/editor/creator/deleter incl. mapping/rule entities), `sw6oidc_passkey_credential` (viewer/deleter), `sw6oidc_session_activity` (viewer, `force_logout`); viewers get `user:read`/`customer:read` for owner names (F-H5/F-N7).
- `service/login-completion.js`, `login-session.js`, `sso-return-route.js`, `webauthn-codec.js`, `user-provider-api.js`, `defer-module-register.js`.
- Extensions: `sw-login`, `sw-inactivity-login`, `sw-admin-menu`, `sw-verify-user-modal`, `sw-profile` (+ `sw6oidc-profile-passkey` page), `sw-profile-index-general`, user detail/listing (`sw-users-permissions-user-*`, `sw-sso-users-permission-user-detail`), `sw-customer-base-info`. Components: `sw6oidc-connect-sso`, `sw6oidc-user-provider-info`, `sw6oidc-rp-id-field`.
- Modules: `sw6oidc-provider` (list + detail; read-only for viewers, re-discovery only when the URL changed, live-test popup opened synchronously and results only accepted from it, `base64_claims` tag field), `sw6oidc-passkey` (listing mixin, links to the owner profile), `sw6oidc-sessions`.

**`Resources/app/storefront/src/`** — passkey login/registration/delete-confirm plugins (endpoints from `path()`, no `window.prompt/alert/confirm`). The built `storefront/dist` is **committed**; rebuild it after changing storefront JS (the CI `assets` job fails on a stale dist). Webpack derives chunk ids and file names from the module paths, so build it in the CI layout: the plugin checked out next to the shop root as `../plugin` (`basePath` `../plugin/src/` in `var/plugins.json`), else the hashes differ from CI.

**`Sw6Oidc.php`** — plugin bootstrap; `uninstall()` (unless "keep user data") drops every plugin table separately in FK-safe order and deletes `Sw6Oidc.config.*` system config and `sw6oidc.*` scheduled tasks (L16).

## Database schema (`Migration1730000001CreateOidcSchema` + follow-up migrations)

- **`sw6oidc_provider`** — one row per IdP: identity/OAuth fields (`app_name`, `client_id`, `client_secret`, `public_client`), endpoints (auto-fillable via discovery), `post_logout_url`, protocol knobs (`scope`, `pkce_flow` strict `S256`/`plain`, `token_endpoint_auth_method`/`revocation_endpoint_auth_method` strict `client_secret_basic`/`client_secret_post`, `base64_claims`, `group_attribute`), behavior flags (`auto_create_customer`/`auto_create_admin`, `disable_non_oidc_*_login`, `show_*_link`, `is_active`, `login_type`), identity policy (`require_email_verified`, `link_existing_accounts`), sync-on-SSO toggles, `allow_superadmin_group_mapping`, `revoke_superadmin_on_sso`, `frontchannel_admin_logout`, ops (`http_timeout` 1–60, `jwks_cache_ttl` 60–86400), health alerting, live-test bookkeeping (`last_test_status` strict `Choice`, L18), FK defaults (`default_customer_group_id`, `default_acl_role_id`).
- **`sw6oidc_attribute_mapping`** — per-provider claim → field mapping (`attribute_type`, `attribute_name`, optional `transform_function`/`transform_params`).
- **`sw6oidc_access_control_rule`** — per-provider login gate.
- **`sw6oidc_role_mapping`** — OIDC group → ACL role / customer group / superadmin (`mapping_type`: `admin_role`|`customer_group`|`superadmin`).
- **`sw6oidc_user_provider`** — permanent IdP binding: `provider_id`, `issuer`, `sub`, polymorphic `user_type`/`user_id`; one per account, one account per `(provider, user_type, sub)`.
- **`sw6oidc_passkey_credential`** — WebAuthn credentials (polymorphic owner, `credential_id`, `credential_id_hash`, `public_key`, `sign_count`, `user_handle`, `nickname`, `disabled_at`).
- **`sw6oidc_session_activity`** — audit log, one row per OIDC/Passkey login.
- **`sw6oidc_session`** — session registry (DBAL only, no entity definition).
- **`sw6oidc_one_time_token`** — `DatabaseAtomicCache` (`key_hash`, encrypted `value`, `expires_at`).
- **`sw6oidc_node_heartbeat`** — `hostname`, `last_seen_at`.

## Extension points / events (`src/Event/`)

All implement `ShopwareEvent` (have `getContext()`), dispatched via `event_dispatcher`:
- `AttributeMappingCompletedEvent` — end of `AttributeMapper::map()`, every OIDC login. Listeners replace the readonly `MappedProfile` via `setProfile()`; the email is re-validated afterwards.
- `CustomerBeforeCreateEvent` / `AdminBeforeCreateEvent` — right before create; `getPayload()`/`setPayload()`. `id` re-forced afterwards; for admins the email is forced back to the verified claim and escalations (`admin`, `aclRoles`) are logged — a listener can still grant superadmin, deliberately.
- `CustomerAfterCreateEvent` / `AdminAfterCreateEvent` — read-only, after create + binding. Not for existing accounts. Customers additionally get core's `CustomerRegisterEvent`.
- `PasskeyRegisteredEvent` — after any passkey registration: audit log entry (`LogAware`) and Flow Builder trigger `sw6oidc.passkey.registered` (owner as mail recipient).

## Architecture — Provider save-time validation & password-login enforcement

- **SSRF** — `Service/Security/SsrfUrlValidator`: https only, every resolved IP public. `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1` allows http/private hosts (dev only); unresolvable hosts always blocked. Used by discovery, connection test and `Sw6OidcProviderWriteGuardSubscriber` (`PreWriteValidationEvent`) for `well_known_config_url` + the fetched endpoints + the (decrypted) webhook URL. Violations carry the camelCase property path + `SW6OIDC_URL_BLOCKED`.
- **Runtime SSRF guard** — `sw6oidc.http_client` (`Sw6OidcHttpClientFactory`) wraps core's client in `NoPrivateNetworkHttpClient` (resolved-IP check per connection and redirect) unless the insecure flag is set, with `max_redirects: 0` set on the *outer* client (the wrapper follows redirects itself, R3-M2; M12; `AvatarFetcher` opts in per request). `OidcHttpClient` retries only GETs, once after 500 ms on transport errors, never blocked addresses; exception messages omit query strings (M3). Revocation uses `postFormIgnoringResponseBody()`: only the status counts, since an RFC 7009 success body may be empty.
- **Client secret** — required for confidential clients (`SW6OIDC_CLIENT_SECRET_REQUIRED`; the column is nullable for public clients, R3-M23), never copied by a clone (`ResetOnClone`). Changing a URL the secret/tokens are sent to (`CREDENTIAL_URL_FIELDS`), or turning a public client confidential, requires the secret in the same save, decided on the *stored* `public_client` (`SW6OIDC_SECRET_REQUIRED_FOR_ENDPOINT_CHANGE`, N-M12, R3-M4).
- **SSO-only invariant** (`Service/Security/SsoOnlyInvariant`, R3-H7) — whenever Administration password login is effectively off, an *active* admin is bound to an *active, admin-serving* provider. Every write that can change it is checked on its result: provider insert/update/delete (flag, `is_active`, `login_type`, delete, issuer disconnect), user deactivation/deletion, admin unlink (which also needs `user-verified`). Turning the policy on also needs a visible SSO button (`SW6OIDC_NO_VISIBLE_LOGIN`) and, while active admins have no binding, the acting admin's confirmation (`SW6OIDC_LOCKOUT_UNBOUND_USERS`; `confirm-lockout`, `user-verified`; CLI counts as confirmed). Customer password login needs a bound customer of this provider (`SW6OIDC_LOCKOUT_GUARD`). A write is refused only when it makes things worse.
- **Session revocation** — when the effective policy turns on, whichever field caused it (after commit, `PasswordSessionRevocationMessage` on the message queue), `PasswordSessionRevoker` ends sessions of accounts **without** any SSO binding (admin refresh tokens; customer contexts in batches of 500, guests excluded) (H8.3, R3-M21).
- **Enforcement** — `PasswordLoginPolicy::isPasswordLoginDisabled($loginType)`: true when any *active* provider serving that login type has the flag (shop-wide). Password path only; OIDC/Passkey unaffected.
  - Storefront/Store API: `PasswordLoginGuardLoginRoute` (core `LoginRoute`), `PasswordLoginGuardRegisterRoute` (registration; guest checkout stays allowed) and `PasswordLoginGuardRegisterConfirmRoute` (double opt-in confirm) throw `PasswordLoginDisabledException` (plain 403 `HttpException`, `SW6OIDC_PASSWORD_LOGIN_DISABLED`; Storefront flash via `PasswordLoginDisabledExceptionSubscriber`, N-L18). The login template hides the password form only when an SSO or passkey button is shown (F-N4); the register template hides the registration form.
  - Admin: **`PasswordLoginGuardUserRepository`** decorates core's OAuth `UserRepository`, so no request encoding can bypass it (N-H1). `AdminPasswordLoginGuardSubscriber` (`kernel.request` after the router) parses the body like the token endpoint (any JSON content type), refuses undeterminable grant types, and answers password grants and `client_credentials` with **user** access keys (SWUA…) with a descriptive 403 (`client_id` normalised like League). The real enforcement for user access keys is **`PasswordLoginGuardClientRepository`**, which decorates core's `ClientRepository` (also covers core's MCP authentication, R3-M20). `SW6OIDC_ALLOW_USER_ACCESS_KEYS=1` opts out; integration keys unaffected. `login-options` returns `passwordLoginDisabled` for the `sw-login` override.
  - Break-glass: `SW6OIDC_ALLOW_PASSWORD_LOGIN=1` (turns the policy and the user-lockout guard off).

## Architecture — Secrets at rest

- `client_secret` and `health_alert_webhook_url` are `Sw6OidcEncryptedField`s (serializer encrypts with purpose `sw6oidc_provider.<column>`), write-only over the Admin API (no `ApiAware`), `ResetOnClone`.
- **`Sw6OidcEncryptor`** — v2 envelope `sw6oidc_v2:` + base64(nonce ‖ ciphertext): XChaCha20-Poly1305 with a key derived per **purpose** (keyed BLAKE2b over an `APP_SECRET`-derived master key) and the purpose as associated data (N-L4); v1 (`sw6oidc_v1:`, secretbox) still readable, upgraded by `Migration1790800010`. `decrypt()` never throws (undecryptable envelopes are passed through and logged so hydration works); code about to *use* a value calls `decryptOrNull()`/`isEncrypted()`. `Sw6OidcProviderEntity::getUsableClientSecret()` = decrypted secret or null (N-L5) — used by token exchange, revocation, connection test and export. An envelope written back is accepted only if it decrypts with this installation's key.
- Also used for one-time token values and registry session keys/tokens. Rotating `APP_SECRET` makes all of it undecryptable (secrets must be re-entered; registry/one-time entries are effectively dropped).
- **`ProviderSecretPayloadScrubber`** — blanks `clientSecret`/`healthAlertWebhookUrl` in `sw6oidc_provider.written` payloads (core decodes written fields), so other listeners/webhooks never see plaintext (N-L6).

## Architecture — Logging

- Channel `sw6oidc` (service `sw6oidc.logger`, a `Monolog\Logger`) → **`ConfigurableLevelHandler`** → `RotatingFileHandler` (`var/log/sw6oidc-<env>.log`, daily, 14 files kept, M22).
- Level: `SW6OIDC_LOG_LEVEL` (default `warning`, parameter `sw6oidc.default_log_level`), or `debug` while the plugin setting `debugLoggingEnabled` is on (read lazily once per request, reset via `kernel.reset`) (H9, Future Improvement 1).
- **`SensitiveDataProcessor`** masks values under credential-like context keys in any spelling (recursively) and credential query parameters (`state`, `nonce`, `sw6oidc_nonce`, `code`, `id_token_hint`, tokens, …) inside any string, message included — also at the start of a string, after `;`, URL-encoded inside another URL, as JSON members, `Bearer`/`Basic` values and bare JWTs; non-string values under credential keys; exceptions are reduced to class + scrubbed message (R3-L45).

## Architecture — CSP

Shopware 6.7 has **no CSP contribution API**: `CoreSubscriber::setSecurityHeaders()` sets the header from the fixed `shopware.security.csp_templates`, and only if the response has none yet. `Subscriber/Sw6OidcCspSubscriber` (`kernel.response`, priority -10, storefront/administration scopes) appends the origins from `Sw6OidcCspHostCollector` (https origins of all active providers' endpoints, cached in `cache.app`, invalidated on provider written/deleted) to `form-action`/`connect-src`/`frame-src`/`img-src` in **every** `Content-Security-Policy` and `Content-Security-Policy-Report-Only` header (N-L15) — **only if the directive is already present and isn't `'none'`**; it never adds a directive. With the stock templates it's a no-op. The live-test popup and the step-up popup set their own nonce'd CSP.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `SW6OIDC_REDIS_DSN` | empty | Redis for one-time tokens (`redis://`/`rediss://`); empty = database store |
| `SW6OIDC_LOG_LEVEL` | `warning` | base level of the `sw6oidc` log channel (`debugLoggingEnabled` overrides to `debug`) |
| `SW6OIDC_HEALTH_TOKEN` | empty | if set, `/sw6oidc/health` requires `X-Sw6oidc-Health-Token` |
| `SW6OIDC_SESSION_ACTIVITY_RETENTION_DAYS` | `90` | activity-log retention, `0` = keep forever |
| `SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP` | `0` | `1` = store activity IPs truncated (IPv4 /24, IPv6 /64) |
| `SW6OIDC_ALLOW_PASSWORD_LOGIN` | `0` | break-glass: re-enable password login despite `disable_non_oidc_*_login` |
| `SW6OIDC_ALLOW_USER_ACCESS_KEYS` | `0` | `1` = allow `client_credentials` with user access keys in SSO-only mode |
| `SW6OIDC_ALLOW_INSECURE_IDP_URLS` | `0` | dev only: allow http/private IdP URLs, disables the runtime SSRF wrapper |

E2E-only: `SW6OIDC_E2E_SHOP_IMAGE`, `SW6OIDC_E2E_SHOP_URL` (see `tests/E2E/README.md`).

## Known gaps / implementation notes

Do not assume the following are fully wired just because the schema or config UI suggests they are:

- Back-/Front-Channel Logout and forced logouts end *all* sessions of an admin user (see State storage), and only know sessions registered in `sw6oidc_session` (logins before `Migration1790800006` lived in a cache pool and are not targetable). Passkey sessions are never in the registry.
- Without Redis, multi-node setups are correct for one-time tokens (DB), but the rate limiter, JWKS cache and the other `cache.app` stores are per node unless Shopware's cache pools are shared; `InfrastructureInspector` warns (`multi_node_without_redis`).
- OIDC step-up needs the IdP to return `auth_time`; the E2E OIDC step-up spec is skipped when Dex doesn't.
- `UserProviderBindingService::unbind()` is called by the Administration unlink action and `UserProviderCleanupSubscriber`.
- Domain exceptions extend `Exception\Sw6OidcException` (a Shopware `HttpException` with an HTTP status and a stable `SW6OIDC_*` code, R3-L10); build them with `new X($message, $previous)`.
- A provider with bound accounts can't be deleted through the plain DAL/API (`SW6OIDC_PROVIDER_HAS_BINDINGS`): the Administration confirms and calls `POST /api/_action/sw6oidc/provider/{id}/delete` (`sw6oidc_provider:delete`), which sets the context state `Sw6OidcProviderWriteGuardSubscriber::STATE_BINDING_LOSS_CONFIRMED` (R3-L43).
- `TestResultTranslator` reads the Administration snippet files at runtime on purpose (one source of wording for the popup and the provider page); this needs the plugin's sources, which a Composer install always has (R3-L48, decided).
- `Context::createDefaultContext()` remains only where no request context exists (anonymous pre-auth routes, subscribers, CLI); the core OAuth internals the admin bridge depends on are pinned by `CoreOAuthContractTest` (R3-L49).
- Integration suite (`tests/Integration/`, `phpunit.integration.xml.dist`): real Shopware kernel via core's `TestBootstrapper` (separate `<db>_test` database, needs `SHOPWARE_PROJECT_ROOT` and runs with *the shop's* PHPUnit/autoloader — the plugin's own `vendor/` has a second `shopware/core`), Dex from `tests/Integration/docker-compose.yml` (plain HTTP → `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1`, `APP_URL=http://localhost:8000` must match the Dex client's redirect URIs). `BackChannelLogoutTest` needs no Dex (JWKS seeded into `cache.app` under `sw6oidc_jwks_<sha256(url)>`), nor does `DatabaseAtomicCacheTest`; the Dex tests (`StorefrontOidcLoginTest`, `AdminOidcLoginTest`, `AccessControlRulesTest`) drive Dex's login form with `Support/DexLoginDriver` and skip when Dex is down. CI writes the shop's test settings to `.env.test.local` (Dotenv ignores `.env.local` when `APP_ENV=test`; with the template's short `APP_SECRET`, admin token signing fails). Provider fixtures need resolvable hosts or IP literals.
- Browser E2E (`tests/E2E/`, Playwright + TypeScript): dockware Shopware 6.7.14.2 lifted to 6.7.15 by the global setup (`composer require … -W`, `system:update:finish`, container restart) with the plugin mounted; report/traces under `SW6OIDC_E2E_OUTPUT_DIR` (CI: the runner temp dir, the container owns the checkout), Dex as IdP (a `dex` hosts entry so shop and browser share one issuer URL), idempotent global setup through the Admin API, WebAuthn via the CDP virtual authenticator (UV, resident keys). Specs `01-storefront-oidc` … `05-admin-step-up-and-passkey`, one worker, in order.
- Unit tests (`tests/Unit/`, 876 tests): OIDC core (state/PKCE, JWT, claims merge), identity resolution, provisioning, group mapping, bindings, WebAuthn ceremonies against the real 5.x validators (`SoftwareAuthenticator` test helper), state stores, and every security/config component.
- No Docker/dev Shopware environment for development committed (only the test environments). Deploy note: PHP-FPM opcache may keep serving stale plugin classes after an update — reset it (e.g. `cachetool opcache:reset`) in addition to `cache:clear`.

## Tooling

- `phpstan.neon.dist` — level 8 (DAL generics annotated: `EntityRepository<…Collection>`), scans `src`; `phpstan.tests.neon.dist` — level 5 over `tests/Unit` (excludes `src/Resources`), `treatPhpDocTypesAsCertain: false` (much of the code validates untrusted third-party data at runtime against its own PHPDoc shapes).
- `psalm.xml` — `errorLevel="4"`, `findUnusedCode="true"` against `psalm-baseline.xml` (the DI/DAL false positives: constructors, entity accessors, routes, subscribers; new unused code fails); suppressions for `MissingOverrideAttribute` (PHP 8.2 predates `#[\Override]`), `UndefinedDocblockClass` (Shopware DAL generics stubs), `InternalMethod` (`Context::createDefaultContext()` pre-auth; plus file-scoped for the encrypted-field serializer and the provider write guard), `UndefinedClass` (`\Redis`, optional ext-redis).
- `phpcs.xml.dist` — PSR12 base, relaxed line length (soft 180 / hard 200).
- `rector.php` — `withPhpSets()` (PHP 8.2 floor from `composer.json`), `deadCode`/`codeQuality`/`typeDeclarations`/`earlyReturn` sets.
- CI (`.github/workflows/ci.yml`) — 7 jobs on push/PR to `main`, all blocking, actions pinned to commit SHAs, `permissions: contents: read` (R3-L51): `lint` (PHPCS, plus a gate against deprecated `sw-*` admin components and `$tc`), `static-analysis` (PHPStan src + tests, Psalm; PHP 8.2 and 8.5), `rector` (dry-run, fails if changes remain), `tests` (PHPUnit matrix PHP 8.2/8.3/8.4/8.5, coverage uploaded), `integration` (fresh `shopware/production` 6.7 + MySQL + Dex, plugin as path repository), `assets` (installs the plugin, `bin/console lint:container`, builds Administration + Storefront bundles, fails on stale committed bundles), `e2e` (Playwright suite incl. `00-admin-smoke`, uploads the report).
