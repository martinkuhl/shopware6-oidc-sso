# Implementation plan for the open topics of `Code-Review.md` (after revision 5)

| | |
|---|---|
| **Source** | `Code-Review.md` revision 4, with the revision 5 status table (2026-10-06) |
| **State** | **Done (2026-10-07, review revision 7).** Phases Q2–Q9 are implemented in `af243ae` … `a9577b4`; see the status table in `Code-Review.md`. Still open: running the integration and E2E suites (Q0/Q1 gate; CI now runs them as blocking jobs), the partials R3-L29 and R3-L49, and the optional roadmap. R3-L48 was closed as won't fix. |
| **Plugin version after this work** | `0.2.0` |
| **Structure** | Phases Q0–Q9, plus an optional roadmap phase. One commit per phase or more; finding IDs go in the commit messages, as before. |

Paths are relative to `src/` unless they start with `tests/`, `.github/` or `src/Resources/`. Admin JS paths start at `src/Resources/app/administration/src/`. The full description of each finding is in `Code-Review.md`.

---

## What revision 5 changed (context for the open work)

New building blocks you will meet in the code:

| Piece | Purpose |
|---|---|
| `Service/Security/SsoOnlyInvariant` | The one SSO-only check (R3-H7), asked by the provider guard, `AdminLockoutGuardSubscriber` and the admin unlink. Counts only active admins whose binding matches the provider's current issuer. |
| `Subscriber/ProviderTrustGuardSubscriber` | Trust-relevant provider fields, privileged role mappings and identity mappings/access rules of admin providers need a superadmin; audit log (R3-H4). |
| `Subscriber/TrustEntityWriteGuardSubscriber` | Passkey credentials and bindings are written by the plugin only (R3-H2, R3-H3). |
| `Service/Session/SessionAuthenticationClock` | "Freshly authenticated" per browser session (PHP session), for Storefront linking and passkey registration (R3-H6, R3-M5). |
| `Service/Passkey/PasskeySessionTerminator` + `Subscriber/PasskeyDeletionSubscriber` | Deleting a passkey ends the sessions it logged in (R3-M6). |
| `Service/Provisioning/AdminRoleStore` + `sw6oidc_managed_acl_role` | Managed-only role sync, race-free superadmin revoke (R3-M11). |
| `binding_scope`, `issuer_hash` on `sw6oidc_user_provider` | Identity key with issuer and sales-channel scope (R3-M9, R3-M14). |
| `IssuerChangeConfirmationStore`, `LockoutConfirmationStore` | Decisions in the atomic store, keyed by provider and admin, behind `user-verified` (R3-M22, R3-M9). |
| `PasswordLoginGuardClientRepository` | User access keys refused at core's `ClientRepository` (R3-M20). |
| Migrations 13–18 | Nullable secret, activity passkey hash, admin RP ID, logout style, binding key, managed roles. |

---

## Ground rules (unchanged)

1. Test first for anything observable. A failing test reproduces the finding, then the fix.
2. `composer ci` stays green (PHPCS, PHPStan, Psalm, Rector, unit tests). After Q0, the `integration`, `e2e` and `assets` CI jobs are blocking too.
3. Rebuild the committed bundles whenever admin or storefront JS changes. Build only this plugin: regenerate `var/plugins.json` with `bin/console bundle:dump`, keep only the `Sw6Oidc` entry, run `bin/build-administration.sh` / `bin/build-storefront.sh` with `SHOPWARE_SKIP_BUNDLE_DUMP=1` (and `SHOPWARE_ADMIN_BUILD_ONLY_EXTENSIONS=1`, `SHOPWARE_SKIP_THEME_COMPILE=true`), then restore `var/plugins.json`. This keeps other plugins' files untouched.
4. Migrations continue at `Migration1790800019…`, idempotent; destructive steps in `updateDestructive()`.
5. Finding IDs in code comments only where the code would otherwise look arbitrary.
6. Update `CLAUDE.md` and `TECHNICAL_DOCUMENTATION.md` in the same commit as the behaviour change.
7. Mark findings `Fixed (<commit>)` in the revision 5 status table of `Code-Review.md`.

---

## Phase overview

| Phase | Theme | Items | Size |
|---|---|---|---|
| **Q0** | Make the test gate real; run the suites that weren't run | R4-L7 (rest), R3-L51, F-1, F-8 | M |
| **Q1** | Follow-ups of the fix round | F-1 … F-10 | M |
| **Q2** | Passkey and step-up Lows | R3-F9, R3-L13–L19, R3-L41 | M |
| **Q3** | State, sessions, logout Lows | R3-L8, L9, L30–L36, L37, L39, L40 | M |
| **Q4** | Identity and provisioning Lows | R3-L20–L22, L24 (rest), L25–L29 | M |
| **Q5** | OIDC protocol, HTTP, JWT Lows | R3-L1–L4, L6, L7, L12, L44, L45, R4-L1–R4-L4 | M |
| **Q6** | DAL and secrets | R3-L42, R3-L43 (rest), `sign_count` | M |
| **Q7** | Frontend Lows and hygiene | R3-F7, F8, F10–F17, R6-L2, Hygiene 1 and 2 | L |
| **Q8** | Shopware conventions, DI, dependencies | R3-L5, L10, L38, L46–L50, R4-L5, R4-L6 | M |
| **Q9** | Unused code, comments, docs, static analysis, release | Unused-code table, R3-L11, R3-L52, PHPStan level 8, Psalm unused code, version `0.2.0` | M |
| Q10 (optional) | Roadmap | Future improvements 9–11, 14, 15; F-M2, F-M14; L13 | — |

Q0 comes first: the integration and E2E suites were **not run** for the fix round (only the unit suite, plus manual checks against a dev shop's MySQL).

---

## Q0 — Test gate, and run what wasn't run

**Findings:** R4-L7 (rest), R3-L51; follow-ups F-1 and F-8.

1. **Run the integration and E2E suites** against the current branch (`tests/Integration/README.md`, `tests/E2E/README.md`) and fix what breaks. Expected hot spots: spec `05` (step-up and admin passkey, R3-H1), spec `04` (the new three-passkey delete case, R3-F3), spec `03` (SSO-only: the invariant and the confirmation now need `user-verified`), the admin OIDC login (role sync is managed-only now).
2. **HTTP-level integration tests** (`tests/Integration/AdminAuth/`):
   - `POST /api/sw6oidc/admin/token`, `/step-up/token`, `/step-up/passkey/verify`, `/passkey/login-verify` with `Content-Type: application/json` through the kernel (the unit test `AdminTokenIssuerTest` covers the issuer, not the routes).
   - Anonymous failures answer 400/403, never 401 (R3-F5).
3. **Integration tests for the new MySQL-specific SQL** (F-8), which so far was only checked by hand:
   - `AdminRoleStore` (`INSERT IGNORE`, `SELECT … FOR UPDATE`): two concurrent revokes of the last two superadmins leave one.
   - `PasskeySessionTerminator` (`SHA2(token)` match), `Sw6OidcSessionRegistry::prune()` (the correlated `DELETE`s), `PlaceholderAddressSubscriber` (`JSON_REMOVE`).
   - Migrations 17 and 18 on a populated database (legacy bindings, channel-bound customers, mapped roles).
   - DAL write attempts as a non-superadmin integration: `PATCH` passkey `userId`, binding `sub`, provider endpoint → 400 with the right codes (R3-H2–H4).
4. **Admin smoke spec** `tests/E2E/specs/00-admin-smoke.spec.ts`: open every plugin page as superadmin and as a restricted role (viewer of `sw6oidc_provider`), zero console errors; the role editor shows the plugin's privileges (R3-F2).
5. **CI** (`.github/workflows/ci.yml`, R3-L51): remove `continue-on-error` from `assets` and `e2e`; pin actions to commit SHAs; top-level `permissions: contents: read`; static analysis on PHP 8.2 and 8.5. `composer.json`: `config.policy.advisories.block: true`.

**Done when:** every CI job is blocking and green, and the new tests run there.

---

## Q1 — Follow-ups of the fix round

Things revision 5 introduced or deliberately left out.

| # | Item | Change |
|---|---|---|
| F-1 | Suites not run | See Q0. |
| F-2 | Trust fields look editable for non-superadmins | Only a banner explains R3-H4 today. Disable the trust fields (list in `ProviderTrustGuardSubscriber::TRUST_FIELDS`), the superadmin/admin-role mapping rows and admin-provider email/username mappings and access rules for non-superadmins; show the server's `SW6OIDC_SUPERADMIN_REQUIRED` on the field. Depends on Q7 Hygiene 1 (do it on the `mt-*` templates). |
| F-3 | No default notification for "SSO account linked" | `AccountSsoLinkedEvent` ships as a Flow Builder trigger only. Add a mail template type, a default template (de-DE, en-GB) and an **inactive** flow `sw6oidc.account.sso_linked` (Q5 default), via migration. |
| F-4 | Broken configurations from before revision 5 are only refused on save | `ProviderConfigInspector`: report `email_mapping_unverifiable` (transformed or custom-claim email while `require_email_verified` is on, R3-M15) and `bindings_on_previous_issuer` (count of bindings whose `issuer_hash` doesn't match the provider's issuer, R3-M9). Show both in diagnostics and the health check. |
| F-5 | RP ID field placeholders | There are now two `sw6oidc-rp-id-field`s (`passkeyRpId` per sales channel, `passkeyRpIdAdmin`), and both show the Administration host. Give the component a `scope` prop: the admin field shows the `APP_URL` host, the storefront field the selected sales channel's domain host or the plain placeholder. Remove the two "VERIFICATION NEEDED" comments (Hygiene 2). |
| F-6 | Deleting an admin passkey that logged in ends all of that admin's sessions, the current one too | Say so in the "My passkeys" delete confirmation and in the recovery grid. For customers: core keeps one context per customer and sales channel, so ending the key's sessions also ends the customer's own session in that channel. Document both in `TECHNICAL_DOCUMENTATION.md` (Pitfalls). |
| F-7 | CLI import of an issuer change disconnects bindings silently (logged) | `sw6oidc:config:import --rebind-on-issuer-change`: pass the decision to the guard through a context state, so an operator can keep accounts connected. |
| F-8 | MySQL-only SQL is unit-tested against SQLite doubles or not at all | See Q0, step 3. |
| F-9 (= review **R6-L1**) | `SsoOnlyInvariant::unboundActiveAdminIds()` ignores the issuer | Use the same issuer filter as `adminAccessPossible()`, so the confirmation count and the password-session revocation agree with the invariant. |
| F-10 | Sibling module and Authelia | Port `logout_style` to `MartinKuhl/magento2-oidc` (`Model/Service/RpInitiatedLogoutService.php`, same Keycloak bug). Check whether your Authelia version advertises a standard `end_session_endpoint`; if so, `standard` is the better long-term style for it. |

---

## Q2 — Passkey and step-up Lows

| ID | Change |
|---|---|
| R3-F9 | `sw-verify-user-modal`: poll `popup.closed` every 500 ms and reset `sw6oidcStepUpBusy`; close the popup and clear the timer in `beforeUnmount`. Server: for `step_up` flows `OidcAdminAuthController` always renders the `postMessage` page, also with `{error}` on pipeline failures. |
| R3-L13 | `registration-options`: a `consume()` budget per customer; cap at 20 credentials per account. |
| R3-L14 | The four Storefront ceremony POSTs require `Sec-Fetch-Site: same-origin` or an `Origin` equal to the current domain (403 otherwise). |
| R3-L15 | `updateAfterAssertion()`: one `UPDATE … WHERE id = :id AND (sign_count < :new OR :new = 0)`; pass the entity instead of reloading it. |
| R3-L16 | Admin passkey endpoints answer 403 for non-user sources; `Uuid::isValid()` on path ids (→ 404). |
| R3-L17 | Both `webauthn-codec.js`: send `getTransports()` and `getClientExtensionResults()`; store transports, return them in `allowCredentials`. |
| R3-L18 | Storefront passkey page: "disabled" badge; split the block into sub-blocks. |
| R3-L19 | `PasskeyRelyingPartyResolver`: domains from the context, not a DBAL query; passkey grid `addIncludes` without `publicKey`. |
| R3-L41 | `StepUpController::startOidc`/`passkeyOptions`, `OidcAdminAuthController::startLink`: `consume(SCOPE_FLOW_START . ':' . $userId, $ip)`. |

---

## Q3 — State, sessions, logout Lows

| ID | Change |
|---|---|
| R3-L8 | Read the global `backchannel_logout` budget in `isBlocked()` for unresolvable tokens, or stop writing it. |
| R3-L9 | Front-channel: the malformed-request budget only blocks malformed requests. |
| R3-L30 | `Sw6OidcSessionDestructionService`: on 0 deleted rows fall back to `revokeAllCustomerTokens()`. |
| R3-L31 | Activity recorder: one DBAL query (`registry_session_id = :id OR session_key_hash = :hash`) and one `UPDATE`. |
| R3-L32 | `NodeHeartbeat` from web requests only (throttled `kernel.terminate`), not from the task handler. |
| R3-L33 | Revocation in `RpInitiatedLogoutService`: fixed 3 s timeout, or an async message. |
| R3-L34 | Migration: delete orphaned `sw6oidc_session` rows, then FK to `sw6oidc_provider` `ON DELETE CASCADE`. |
| R3-L35 | `RedisAtomicCache`: encrypt values like the DB store. |
| R3-L36 | `HealthCheckController` without `SW6OIDC_HEALTH_TOKEN`: `{status}` only. |
| R3-L37 | `SessionActivityController::forceLogout`: refuse admin targets unless the caller is an admin. |
| R3-L39 | `RedisConnectionFactory` without APCu: static plus temp-file "down" marker. |
| R3-L40 | Store `sha256(sid)` in `sw6oidc_session_activity.sid` (migration hashes existing values). |

---

## Q4 — Identity and provisioning Lows

| ID | Change |
|---|---|
| R3-L20 | `AttributeMapper`: `EmailIdnConverter::encode()` before validating and looking up. |
| R3-L21 | Truncate profile values with `mb_substr` to the DAL limits in both provisioning services (constant map in `MappedProfile`). |
| R3-L22 | `AvatarFetcher`: `max_duration: 10`; sniff bytes with `getimagesizefromstring()`; PNG/JPEG/GIF/WebP only. |
| R3-L24 (rest) | `OidcCallbackController`: catch `CustomerProvisioningDeniedException` as a policy denial (flash message, not counted by the rate limiter); log ids, never emails. The admin side and the customer exception message are done. |
| R3-L25 | Username dedup: one `LIKE 'base%'` query; random 4-hex suffix after 3 collisions. |
| R3-L26 | Customer email lookup: `active = 1`, sorted by `createdAt DESC`. |
| R3-L27 | `OidcCallbackController`: `register()`/`recordLogin()` failures are logged, never turn a completed login into "login failed". |
| R3-L28 | `OidcAdminAuthController::callback`: refuse inactive admins right after resolution, before any side effect. |
| R3-L29 | Extract the shared account resolution; `loginByCustomerId()` takes the entity; skip no-op sync updates. |

---

## Q5 — OIDC protocol, HTTP, JWT Lows

| ID | Change |
|---|---|
| R3-L1 | `ProviderResolver::getActiveById()`: `Uuid::isValid()` first, else `ProviderNotFoundException`. |
| R3-L2 | `RelayStateValidator`: `D` modifier; test with `%0A`. |
| R3-L3 | `BrowserBinding`: re-issue the cookie on every flow start. |
| R3-L4 | `sub`-required check in `ClaimsMerger::merge()`, shared with the live test. |
| R3-L6 | `ClaimsNormalizer::flattenRecursive`: decode object keys of `base64_claims`; parity test with access rules. |
| R3-L7 | `JwtVerifier::verify()`: `string $expectedNonce`, delete the skip branch. |
| R3-L12 | `LoginType::Test`; typed `locale` on `AuthorizationFlowContext` instead of `relayState`. |
| R3-L44 | Test endpoints: clamp `httpTimeout` 1–30, cast inputs (400 on wrong types); `OidcConnectionTestService` gets `bool $hasSecret`. |
| R3-L45 | `SensitiveDataProcessor`: leading `code=`, JSON bodies, `Bearer`/`Basic`, URL-encoded URLs, `;` params, more keys, non-string values, exception messages; one table-driven test. |
| R4-L1 | Reject a `crit` protected header. |
| R4-L2 | Non-numeric `nbf`/`iat` → `InvalidJwtException`. |
| R4-L3 | `ES256/384`, `PS256` (+ `EC` keys in `candidateKeys()`); allowed list = discovery ∩ supported; the connection test fails clearly on an empty intersection. |
| R4-L4 | Callbacks: truncate `error` (64) and `error_description` (200), log at `notice`, count unknown-state error callbacks. |

---

## Q6 — DAL and secrets

| ID | Change |
|---|---|
| R3-L42 | Lazy decryption: the entity keeps the envelope; `Service/Security/ProviderSecretProvider::clientSecret()` decrypts at the point of use and logs an undecryptable secret once per request; the serializer's `decode()` stops decrypting; `jsonSerialize()` never contains the secret. |
| R3-L43 (rest) | `Choice` on `pkce_flow` (normalise `s256`) and `login_type`; `Range` on `http_timeout` (1–60) and `jwks_cache_ttl` (60–86400); `Required` on NOT NULL booleans; drop `claim_encoding` (definition, entity, admin JS `provider.claimEncoding = 'none'`, column in `updateDestructive`). Provider delete with bound accounts: confirmation dialog listing the count, API refuses without the confirmation (Q7 default). Done: `user_type`/`mapping_type` `Choice`, binding `UpdatedAtField`. |
| Unused | Drop `sign_count` (definition, entity, writes; column in `updateDestructive`). |

---

## Q7 — Frontend Lows and hygiene

Start with Hygiene 1 as its own commit, so the other fixes land on the migrated templates.

| ID | Change |
|---|---|
| Hygiene 1 | **Decided (Q9): migrate everything now.** Every deprecated `sw-*` component in the plugin's templates to its Meteor `mt-*` equivalent (about 30 templates), every `$tc` to `$t`. Check event/prop renames against `vendor/shopware/administration` 6.7. CI grep step fails on new `<sw-(text\|switch\|number\|password)-field\|<sw-card\|<sw-button` or `$tc(`. |
| Hygiene 2 | See F-5. |
| R3-F7 | `sw6oidc-profile-passkey`: `mt-label` → `mt-badge`. |
| R3-F8 | `sw-profile-index-general`: extend `sw_profile_index_general_information` with `{% parent %}` plus a sibling card. |
| R3-F10 | `sw-login`: override only the user field, password field and submit blocks, so "Keep me logged in" stays. |
| R3-F11 | Listing pages: drop the extra `created()` fetch; passkey list writes `ownerNames` after the request-id check. |
| R3-F12 | Provider detail: request counter for `loadEntity()`/`loadFormContext()`. |
| R3-F13 | Sessions list: "Only active" also filters expired rows; "Force logout" disabled on them. |
| R3-F14 | Provider detail: `:disabled="!canEdit"` on every select, tag field and context menu (together with F-2). |
| R3-F15 | Meteor badge variants (`critical`, `positive`, …). |
| R3-F16 | `snippetOr()` for every dynamic key (`atomicStore.*`, `infrastructureWarning.*`, `testMessage.*`). |
| R3-F17 (rest) | `role="alert"`/`aria-live="polite"` on the admin error containers (the storefront dialog is done). |
| R6-L2 (review revision 6) | `acl/index.js` `registerWhenReady()`: don't give up after 5 s. Wait for core's ready signal (the `defer-module-register.js` mechanism), or poll without a hard limit. Remove the unreachable duplicate `return;`. |

Rebuild both bundles at the end (ground rule 3); the Q0 smoke spec covers every page.

---

## Q8 — Shopware conventions, DI, dependencies

| ID | Change |
|---|---|
| R3-L5 | Required `BrowserBinding` in `OidcSecurityHelper` and required dependencies in `OidcLiveLoginTestService`; tests use doubles. |
| R3-L10 | `Sw6OidcException extends HttpException` with `SW6OIDC_*` codes; the 17 domain exceptions become subclasses. |
| R3-L38 | `SHOW COLUMNS` guards in the three early migrations. |
| R3-L46 | Twig extensions → `twig.runtime`; `lazy="true"` on the write guards; pending state cleared on `WriteFailedEvent`/`kernel.reset` (the provider guard now resets per event); `sw6oidc.logger` service id instead of the fake `OidcLogger` FQCN; encryption purposes as constants. |
| R3-L47 | Memoise `StorefrontLoginOptionsExtension` per request. |
| R3-L48 | `TestResultTranslator`: Symfony translations instead of reading the admin snippet files. |
| R3-L49 | One `Service/AdminAuth/CoreOAuthBridge` for the `@internal`/`BecomesInternal` dependencies (now also `ClientRepository`, decorated by `PasswordLoginGuardClientRepository`), with a test that fails when a class disappears; pass `Context` down where a request context exists. |
| R3-L50 | Share `accessTokenJti()` and `ERROR_CODE`; `LoginType::Admin->value` instead of `'admin'` literals. |
| R4-L5 | `OidcCustomerLoginRoute` → `AccountService::loginById()` with `CustomerSalesChannelBinding::allows()` as pre-check; delete the class. |
| R4-L6 | `composer.json`: drop `league/oauth2-server`, `symfony/psr-http-message-bridge`, `nyholm/psr7` (core provides them; `AdminTokenIssuer` uses `Nyholm\Psr7\Factory\Psr17Factory` and `HttpFoundationFactory` from core's dependencies); `web-token/jwt-library: ^4.0` instead of `jwt-framework` (Composer only, Q10). |

---

## Q9 — Unused code, comments, docs, static analysis, release

1. **Delete:** `SsrfUrlValidator::isInsecureModeEnabled()`, `PasskeyCredentialRepository::findOneByCredentialId()`, `UserProviderBindingService::assertNotBoundToDifferentProvider()`, `Sw6OidcSessionRegistry::resolveByUser()`, `AdminLoginNonce::$browserBinding`, `Sw6OidcSession::$createdAt`/`$salesChannelId`, the constructor defaults `'PT10M'`/`'P1W'`, the duplicate admin snippets `sw6oidc.login.*` (the inactivity modal now uses `sw-login.sw6oidc.login.*`), the storefront snippet `sw6oidc.passkey.reauthRequired`. Adjust the tests. Already gone: the `AdminTokenIssuer` request mutation, `AdminPasskeyLoginTokenTracker`, `LockoutGuard`, the registry's `$customerTtlSeconds`.
2. **Make private:** `OidcSecurityHelper::deriveCodeChallenge`, `OidcCallbackResult::subject`, `RpInitiatedLogoutService::revokeToken`, `SsrfUrlValidator::isPublicIp`, `Sw6OidcRateLimiter::clientKey`, `destroyCustomerSession`, `destroyAdminSessions` (now also used by `PasskeySessionTerminator` and `PasswordSessionRevoker` — keep `destroyAdminSessions` public or route them through `destroyAllForUser()`).
3. **R3-L11:** merge the double docblocks; fix the stale comments listed in the Unused-code table.
4. **R3-L52:** full documentation pass. `CLAUDE.md` and `TECHNICAL_DOCUMENTATION.md` were updated for the revision 5 behaviour; still wrong: "19 attribute types" (22), "the passkey list links to the owner profile", the L13 deferral reason, the unit test count.
5. **Static analysis:** `phpstan/phpstan-shopware` or DAL generics stubs, fix the remaining level-8 errors as real fixes, raise to level 8 for `src/` and level 5 for `tests/`; Psalm `--find-unused-code` with a DI-aware baseline.
6. **Release:** version `0.2.0` in `composer.json`, CHANGELOG `[Unreleased]` → `[0.2.0]`.

---

## Q10 — Roadmap (optional, after release)

From `Code-Review.md` "Future improvements", what is not done yet:

- **9** passkeys: conditional mediation (`autocomplete="username webauthn"`), `PasskeyCredentialDeletedEvent`, a clone-detection Flow trigger, one shared ceremony service.
- **10** response-size caps on token, userinfo and JWKS; keep `error`/`error_description` for diagnostics; separate HTTP clients for the IdP and for user content.
- **11** enforce `S256` PKCE unless discovery lacks it; check `typ: logout+jwt`.
- **14** a `Configuration` tree for the `SW6OIDC_*` env vars; autowiring (deferred L13).
- **15** a small pre-auth admin bundle (closes F-M2, F-M14 and the early-execution class of R3-F2).
- Granular admin session termination (refresh-token lineage per login), which would make force logout, IdP logout and passkey deletion end one admin session instead of all.

---

## Decisions

Settled earlier (2026-10-05) and still valid: Q6 one SSO binding per sales channel; Q8 Authelia is in use; Q9 migrate all admin components now; Q10 Composer only; Q11 breaking changes are fine; Q12 continue on `fix/code-review-rev2`.

Taken with the plan's defaults in revision 5, because they were unanswered — please confirm or overrule (see Open questions):

| # | Default implemented |
|---|---|
| Q1 | Trust-relevant provider settings: **superadmins only** (plus CLI and system scope). |
| Q2 | Role sync **multi-valued and managed-only**, seeded from current roles that a mapping grants. |
| Q3 | Registry liveness **derived from core's tables** (`refresh_token`, `sales_channel_api_context`). |
| Q4 | Issuer change with bound accounts: **suspend until a superadmin decides** (re-bind or disconnect). |
| Q5 | "SSO account linked": **trigger only**; default flow and mail template not shipped yet (F-3, inactive when shipped). |
| Q7 | Provider delete with bindings: **confirmation dialog plus API flag** — not implemented yet (Q6). |

## Open questions

| # | Question | Default if unanswered |
|---|---|---|
| Q1 | Should a dedicated grantable privilege (`sw6oidc_provider:security`) be offered instead of "superadmin only" for trust-relevant provider settings? Today even creating a provider needs a superadmin. | Keep superadmin only. |
| Q4 | Issuer change: is "re-bind or disconnect" the right choice, or should a re-bind always happen when the old and new issuer share the same host? | Keep the explicit decision. |
| Q5 | Ship the "SSO account linked" mail flow inactive (merchant enables it) or active? | Inactive. |
| Q7 | Provider delete with bindings: confirmation dialog plus API flag, or refuse while bindings exist? | Confirmation. |
| Q13 | Can the dockware + Dex E2E setup run reliably in GitHub Actions, so `e2e` becomes blocking? | Blocking after Q0 step 1 passes locally. |
| Q14 (new) | Admin passkey deletion ends **all** of that admin's sessions (tokens can't be targeted). Acceptable, or end only when the deleted key logged in a session that is still within the refresh-token TTL? | All sessions (safer). |
| Q15 (new) | CLI config import that changes an issuer: disconnect bindings (today) or re-bind? See F-7. | Disconnect, with an opt-in flag. |
