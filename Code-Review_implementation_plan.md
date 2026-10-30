# Implementation plan for `Code-Review.md` revision 8

| | |
|---|---|
| **Source** | `Code-Review.md` revision 8 (2026-10-30), reviewed commit `7cb8086` |
| **State** | Not started. The plan for revision 7 (phases Q0–Q9) is done; it is in git history (`git show 7cb8086:Code-Review_implementation_plan.md`). |
| **Scope** | 2 High, 10 Medium, 32 Low, the maintainability and unused-code rows, the CLAUDE.md drift. |
| **Plugin version after this work** | `0.3.0` (breaking changes are fine: the plugin has no production installs yet). |
| **Structure** | Phases P0–P9, plus an optional roadmap phase. At least one commit per phase; finding ids (`R8-H1`, `R8-M3`, …) go in the commit messages. |

Paths are relative to `src/` unless they start with `tests/`, `.github/` or `src/Resources/`. Admin JS paths start at `src/Resources/app/administration/src/`. The full description of each finding is in `Code-Review.md`.

---

## Decisions (defaults used unless you decide otherwise)

| # | Question | Default |
|---|---|---|
| D1 | Branch | `fix/code-review-rev8` off `main`, merged through a PR (CI only runs on pushes to `main` and on PRs). |
| D2 | R8-H1: extend `TRUST_FIELDS`, or switch to an editor allow-list? | **Allow-list** (`EDITOR_FIELDS`). Every column not on it needs a superadmin, so new columns are protected by default. |
| D3 | R8-H2: in an imitated Storefront session, refuse sensitive actions or only skip the "fresh" stamp? | **Both.** No stamp, and passkey registration, SSO linking and re-auth answer with a flash message ("not available while logged in as this customer by an administrator"). |
| D4 | R8-L32: how to ask for `auth_time` | `claims={"id_token":{"auth_time":{"essential":true}}}`, **only** when discovery says `claims_parameter_supported: true`. No positive `max_age`. Nothing changes for Authelia. |
| D5 | R8-M9: on a repeat customer login with the same context token, what happens to the older registry entry? | **Kept** (changed during implementation): superseding it at login would drop the older device's `sid`, so that IdP session's back-channel logout would end nothing. Instead, logout ends every entry of the context token and revokes each one's tokens. |
| D6 | R8-M10: duplicate (issuer, client_id) providers | **Allowed** (separate customer and admin rows for one IdP client are legitimate). Back-channel logout runs for every matching provider. |
| D7 | R8-L16: health status `down` | **200** by default with `status: down`; `?strict=1` answers 503. Breaking for anyone who relies on 503: note it in the CHANGELOG. |
| D8 | R8-L25: passkey-only accounts and SSO-only mode | Count an active passkey as "can still log in" in the confirmation prompt (while admin passkeys are enabled). **Narrowed during implementation:** their sessions are still revoked, because that is harmless (they log in again with the passkey) and it ends password-started sessions, the point of the revocation. |

---

## Ground rules

1. Test first for anything observable. A failing test reproduces the finding, then the fix.
2. `composer ci` stays green (PHPCS, PHPStan 8 / 5, Psalm with `findUnusedCode`, Rector, unit tests). The `shopware` and `e2e` CI jobs are blocking.
3. Unit tests must pass in any timezone: P0 sets `date.timezone=UTC` in `phpunit.xml.dist`, and new tests never compare against local-time `strtotime()`.
4. Rebuild the committed bundles whenever admin or storefront JS changes. Build only this plugin (`bin/console bundle:dump`, keep only `Sw6Oidc` in `var/plugins.json`, `SHOPWARE_SKIP_BUNDLE_DUMP=1`, restore `var/plugins.json`). Build the Storefront in the CI layout (the plugin checked out as `../plugin`), or the chunk hashes differ.
5. No new migration files: after PM, schema changes go into the one schema migration (`Migration1790900000CreateSchema`), and the dev database is altered by hand.
6. Finding ids go in code comments only where the code would otherwise look arbitrary.
7. Update `CLAUDE.md`, `TECHNICAL_DOCUMENTATION.md`, `README.md` and `CHANGELOG.md` in the same commit as the behaviour change.
8. Mark each finding `Fixed (<commit>)` in a status table at the top of `Code-Review.md` once its phase lands.

---

## Phase overview

| Phase | Theme | Findings | Size |
|---|---|---|---|
| **P0** | Test baseline | R8-L31 | S |
| **PM** | One schema migration, legacy-data code removed | (new topic, no finding id) | M |
| **P1** | Trust boundaries | R8-H1, R8-H2, R8-M11, R8-L5 | M |
| **P2** | IdP interoperability | R8-M1, R8-L32, R8-L1, R8-L2, R8-L3, R8-L4 | M |
| **P3** | Sessions and logout | R8-M9, R8-M10, R8-L13, R8-L19, R8-L20 | M |
| **P4** | Identity and provisioning | R8-M3, R8-M4, R8-L6–R8-L12 | L |
| **P5** | Storefront addresses | R8-M5, R8-M6 | M |
| **P6** | Passkeys and admin auth | R8-M8, R8-L14, R8-L15, R8-M-3 | M |
| **P7** | Write guards, data layer, queued side effects | R8-M7, R8-L21–R8-L30 | L |
| **P8** | Health | R8-L16, R8-L17, R8-L18 | S |
| **P9** | Maintainability, unused code, docs, release | R8-M-1, R8-M-2, R8-M-4, R8-M-5, R8-M-U, CLAUDE.md drift, version `0.3.0` | M |
| P10 (optional) | Roadmap | Future improvements 2–4, 8–14 | — |

Order: P0, then PM (so the columns this round adds go straight into the one schema migration, never into new migration files), then P1 (security), then P2 (it breaks logins), then P3–P8 in any order, then P9 last (it touches files from every phase).

---

## P0: Test baseline

**R8-L31**
1. `phpunit.xml.dist`: add `<ini name="date.timezone" value="UTC"/>`.
2. `tests/Unit/ScheduledTask/SessionActivityCleanupTaskHandlerTest.php:35-36`: compare against `new \DateTimeImmutable('-30 days', new \DateTimeZone('UTC'))`.
3. Grep `tests/` for other `strtotime(`, `date(` and `new \DateTime(` calls without an explicit timezone, and fix them the same way.

**Done when:** `TZ=Europe/Berlin composer test` and `TZ=UTC composer test` are both green.

---

## PM: One schema migration, legacy-data code removed

**Why:** the plugin has 21 migrations, and about half of them only move data out of shapes that existed for a few days during development: plaintext secrets, v1 envelopes, bindings without `sub`, `claim_encoding`, the button columns. The plugin is in development and installed only in the author's shop, so none of that data exists anywhere else.

1. **One migration.** Replace `src/Migration/*` with a single `Migration1790900000CreateSchema` holding the **final** schema:
   - all 11 tables (`sw6oidc_provider`, `_attribute_mapping`, `_role_mapping`, `_access_control_rule`, `_user_provider`, `_passkey_credential`, `_session_activity`, `_session`, `_one_time_token`, `_node_heartbeat`, `_managed_acl_role`), with every column, index and foreign key;
   - `CREATE TABLE IF NOT EXISTS`, so it is a no-op on an existing install;
   - `updateDestructive()` empty.
   
   Take the column definitions from `SHOW CREATE TABLE` of a fully migrated database, so the result matches what migrations 1–21 produced.
2. **Columns this round adds** (P2 `claims_parameter_supported`) go into that one migration, not into new files.
3. **Remove the code that only existed for pre-migration data:**
   - `Sw6OidcEncryptor`: drop the v1 envelope (`sw6oidc_v1:`, secretbox) and plaintext pass-through. Only v2 remains, so `isLegacy()` goes too.
   - `IdentityResolver` step 2: drop the legacy-binding backfill (`sub = NULL`), along with `UserProviderBindingService::backfillSubject()` and the nullable `sub` handling.
   - `RedisAtomicCache`: drop reading plaintext values (R3-L35 compatibility).
   - `Sw6OidcProviderWriteGuardSubscriber` / the entity: anything that still accepts or upgrades plaintext `client_secret` rows (the "legacy plaintext rows are encrypted on the fly" path of the config export).
   - Passkey `public_key` rows from webauthn-lib 4.x deserialise unchanged, so nothing is needed there.
4. **Tests:** delete the migration tests. Add one test that the migration's statements create every table and column the entity definitions use (definition fields compared with the `CREATE TABLE` columns, also covering R8-L21's NOT NULL check).
5. **Existing install (the author's dev shop):** the old migration rows stay in the `migration` table, which is harmless (Shopware only loads classes that exist). The new migration finds every table and does nothing. The columns added in this round are applied to the dev database once by hand (`ALTER TABLE …`, listed in the commit message), or by reinstalling the plugin (`sw6oidc:config:export` → uninstall → install → import).
6. **Docs:** CLAUDE.md "Migration/" and "Database schema" sections, TECHNICAL_DOCUMENTATION.md, CHANGELOG "Breaking: installs from before 0.3.0 must reinstall".

**Done when:** a fresh `plugin:install` on an empty database creates the same schema as migrations 1–21 did (compare `SHOW CREATE TABLE` output), and `composer ci` is green.

---

## P1: Trust boundaries

### R8-H1: superadmin-affecting flags (D2)
- `Subscriber/ProviderTrustGuardSubscriber.php`: replace `TRUST_FIELDS` with `EDITOR_FIELDS`, the columns a non-superadmin may change:
  - display and behaviour: `app_name`, `is_active`, `sort_order`, `show_*_link`;
  - customer-side flags: `auto_create_customer`, `sync_customer_*`, `default_customer_group_id`, `disable_non_oidc_customer_login`;
  - operations: `http_timeout`, `jwks_cache_ttl`, `health_alert_*` settings, `post_logout_url`;
  - the secret (re-entry only).
  
  Every other column needs a superadmin on update, and every insert of an admin-serving provider does too. In particular that covers `revoke_superadmin_on_sso`, `sync_admin_role_on_sso`, `sync_admin_profile_on_sso`, `disable_non_oidc_admin_login`, `frontchannel_admin_logout`, both `*_auth_method` columns and `logout_style`.
- Admin UI (`module/sw6oidc-provider/page/sw6oidc-provider-detail`): drive `canEditTrust` from the same list. Expose it in `form-context` (`OidcProviderAdminController`), so the list exists only once.
- **Tests:**
  - A unit test per formerly unprotected field: a non-superadmin `PATCH` gets `SW6OIDC_SUPERADMIN_REQUIRED`.
  - A test that fails when a new definition field is in neither list, so whoever adds a column has to decide.

### R8-H2: imitation (D3)
- `Subscriber/CustomerAuthenticationClockSubscriber.php`: return early when `$event->getSalesChannelContext()->getImitatingUserId() !== null`.
- `Service/Session/SessionAuthenticationClock::isFresh()`: take the `SalesChannelContext`, and return false while imitating.
- `Storefront/Controller/PasskeyController` (registration options and verify), `SendAuthorizationRequestController::link()`/`reauthenticate()`, `OidcCallbackController::completeLink()`: refuse while imitating, with a flash message and snippets in de-DE and en-GB.
- Passkey *login* during imitation can't happen (imitation is its own login), so it needs nothing.
- **Tests:** unit tests with a context that has an imitating user id. An E2E case in `04-storefront-passkey`: imitate a customer, open *My account > Passkeys*, and expect the "not available" message.

### R8-M11: guest conversion
- New `Storefront/Service/PasswordLoginGuardConvertGuestRoute` decorating `AbstractConvertGuestRoute`. When `PasswordLoginPolicy::isPasswordLoginDisabled(LoginType::Customer)`, throw `PasswordLoginDisabledException` (the Storefront flash already comes from `PasswordLoginDisabledExceptionSubscriber`).
- Hide the "create account" option on the checkout finish page when the policy is on (template block).
- **Tests:** a unit test for the decorator; integration coverage via `/store-api/account/convert-guest`.

### R8-L5: unlink of a superadmin
- `Controller/Api/OidcUserProviderAdminController::unlink()`: when the target is a superadmin, require the acting user to be a superadmin.
- After unlinking, end the target's sessions: `Sw6OidcSessionDestructionService` for the user, then remove the registry entries.
- **Test:** a non-superadmin with `user:update` unlinks a superadmin and gets 403.

**Done when:** all of the above have tests, and E2E 03, 04 and 05 are green.

---

## P2: IdP interoperability

### R8-M1: Basic credentials
- Build the Basic header in `Service/Oidc/ClientAuthentication`, not in `OidcHttpClient`: `base64_encode(rawurlencode($id) . ':' . rawurlencode($secret))` (RFC 6749 §2.3.1; `rawurlencode`, because fosite, Keycloak and Spring decode it correctly). `OidcHttpClient::postForm()` then takes a ready `Authorization` header value.
- **Tests:** a secret `a+b%2F:c` and a client id containing `:`, round-tripped through `urldecode` the way fosite does it.
- **Manual check:** a login against Authelia with a secret that contains `+`.

### R8-L32: ask for `auth_time` (D4)
- `OidcDiscoveryService`: read `claims_parameter_supported` from discovery and store it. The schema migration (PM) gets `sw6oidc_provider.claims_parameter_supported` (bool, default 0), refreshed on every re-discovery. Show it read-only on the provider page.
- `StepUpService::start()` and `SendAuthorizationRequestController::reauthenticate()`: add `claims={"id_token":{"auth_time":{"essential":true}}}` to `extraParams` when the flag is set. Keep `prompt=login`. No `max_age`.
- `OidcCallbackController`: catch the freshness failure, as its own exception `FreshLoginNotConfirmedException extends InvalidStateException`, thrown by `AuthTimeValidator`. Show its own flash message (`sw6oidc.account.reauthNotConfirmed`) and **don't** call `recordFailure()`. The admin step-up popup gets a matching `error: 'fresh_login_not_confirmed'`, which `sw-verify-user-modal` shows as "Your identity provider did not confirm a new login; use your passkey".
- **Tests:** the builder adds `claims` only with the flag. The callback maps the new exception without counting it.
- **Manual check:** step-up and Storefront re-auth against Authelia still work. Authelia doesn't advertise the flag, or ignores the parameter.

### R8-L1: revocation status
- `OidcHttpClient::postFormIgnoringResponseBody()`: anything outside 2xx throws. The revocation caller already logs failures at warning level.

### R8-L2: one secret resolution
- `ClientAuthentication::forProvider(Sw6OidcProviderEntity $provider, string $authMethod)` resolves the secret itself through `getUsableClientSecret()`. Empty or undecryptable secrets throw `ClientSecretUnavailableException`. `TokenExchangeService::clientSecret()` goes away, and `RpInitiatedLogoutService` catches the exception and skips, as it does today.

### R8-L3: rate limits for `link`/`reauth`
- `SendAuthorizationRequestController::link()` and `reauthenticate()`: `consume(SCOPE_FLOW_START . ':' . $customerId, $request->getClientIp())`. When the budget is exhausted, show a flash message and redirect back to the account page.

### R8-L4: email pair
- `ClaimsMerger::merge()`: take `email` and `email_verified` together from the id_token when it has `email`. Otherwise take both from userinfo.
- **Test:** id_token `email` without `email_verified`, userinfo `email_verified: true` → not verified.

---

## P3: Sessions and logout

### R8-M9: one registry entry per context token (D5)
- `Sw6OidcSessionRegistry::register()` for customers: inside a transaction, select the existing entries with the same `session_key_hash` `FOR UPDATE`, delete them, and return them to the caller. `OidcCallbackController` revokes their IdP tokens (`RpInitiatedLogoutService::revokeTokens()`) after the response decision.
- `findBySessionKey()`: `ORDER BY created_at DESC`. With the dedup there is at most one row, but newest-first is the safe default.
- `Sw6OidcSessionActivityRecorder::recordLogout()`: match the exact `registry_session_id` first, then fall back to the session-key hash. That needs two queries, or one query with `ORDER BY (registry_session_id = :id) DESC`.
- **Tests:**
  - Two registrations with the same key leave one row, and the older one's tokens are handed back.
  - Logout picks the newest entry.
  - Integration: two SSO logins of the same customer, then a logout. The registry is empty and the activity rows are closed correctly.

### R8-M10: back-channel logout for every matching provider (D6)
- `BackChannelLogoutController`: collect every provider from `findByIssuer()` whose client id is in `aud`.
  - Verify the token once, with the first candidate's verifier context. Issuer and JWKS are the same for all candidates.
  - Call `Sw6OidcIdpLogoutHandler::logout()` for each candidate.
  - Answer 500 if any of them fails (the replay marker is removed, as today).
- **Test:** two providers with the same issuer and client id; the session belongs to the second one; the back-channel logout ends it.

### R8-L13: passkey session marker
- Remove `sw6oidc_login_credential_id`: the writes in `PasskeyController.php:282`, the read in `AccountPasskeyController.php:84`, and the constant.
- `AccountPasskeyController::delete()` logs the customer out only if `PasskeySessionTerminator` ended the current context token. The terminator returns the hashes it ended.

### R8-L19: `RedisAtomicCache` in long-running workers
- Implement `ResetInterface` (clear `resolved`), and tag the service `kernel.reset`.
- `RedisConnectionFactory`: on a command error (not only on connect), call `markDown()`.

### R8-L20: batched registry prune
- `Sw6OidcSessionRegistry::prune()`: each of the three DELETEs gets `LIMIT 1000` in a loop with a 30 s time budget, like `DatabaseAtomicCache::prune()`.

---

## P4: Identity and provisioning

### R8-M3: missing groups claim
- `MappedProfile`: add `bool $groupsClaimPresent`, set in `OidcCallbackProcessor`. It is true when the configured `group_attribute` key (or any child key) exists in the raw merged claims, and is not listed in `_claim_names`.
- `AdminProvisioningService::syncRole()` and `CustomerProvisioningService` group sync: skip when it is false, and log a notice once per login.
- `revoke_superadmin_on_sso`: also skipped when it is false. Revoking because nothing resolved is fine only if the claim was actually there.
- **Tests:** Entra overage (`_claim_names.groups`), missing claim, present-but-empty claim (sync runs and removes roles).

### R8-M4: locale and salutation on sync
- New `Service/Provisioning/LocaleResolver`:
  - exact `Locale.code`;
  - normalise `_` to `-`;
  - case-insensitive;
  - language prefix (`de` → the first active `de-*`, preferring `de-DE`).
  
  It returns null when nothing matches.
- `syncProfile()`: write `localeId` only on a match. The en-GB fallback stays for create only. Do the same for `resolveSalutationId()` in customer sync.
- **Tests:** `de`, `de_DE`, `DE-de`, `xx` (no write on sync).

### R8-L6: avatars
- Store the plugin-created media id in `user.customFields.sw6oidc_avatar_media_id`. Replace only that media. If the current avatar is a different media, leave it alone.
- `AvatarFetcher`: reject images whose `getimagesize()` reports more than 4096 px per side.

### R8-L7: `email_domain`
- The operator matches only when `email_verified` is true (same truthiness as the identity resolver). Compare domains punycode-encoded (`idn_to_ascii`), and validate the email after encoding.

### R8-L8: one tokenisation for string groups
- **Decided during implementation: documented, not changed.** Splitting a scalar groups claim would break single-valued claims with names like `"Domain Users"` (Keycloak sends a string when "multivalued" is off; AD names often have spaces), which is worse than the inconsistency. A scalar stays one group for role mapping; an access rule's `contains` keeps tokenising scalars (scope-like claims, N-M11). Both documented in `ClaimsNormalizer` and CLAUDE.md.

### R8-L9: countries
- `CountryResolver`: filter `active = 1`. Prefer countries assigned to the sales channel, then fall back to any active one.

### R8-L10: provisioning duplication (R3-L29)
- Customer path: refuse an inactive bound or email-matched account **before** `syncExisting()`, with a `CustomerProvisioningDeniedException::inactive()` (an account-policy error that isn't counted).
- Extract a `Service/Provisioning/JitAccountCreator::createAndBind(callable $create, string $userType, ExternalIdentity $identity, ?string $bindingScope)` that holds the transaction plus the unique-violation re-resolve. Both services use it.
- Extract `ProfileDiff::withoutUnchanged()`, used by both services.
- Use one fallback-name helper: local part, else `'-'`, with `'0'` handled via `=== ''`.

### R8-L11: config import errors
- Key failures by `"#<index> <appName>"`. Move the `appName` validation inside the per-provider `try`.

### R8-L12: subject-key race
- `UserProviderBindingService::bind()`: on a unique violation, read the binding by subject as well. If the subject belongs to another account, throw `SubjectAlreadyLinkedException`.

---

## P5: Storefront addresses

### R8-M5: `CartValidator`
- New `Checkout/Cart/PlaceholderAddressCartValidator implements CartValidatorInterface` (tag `shopware.cart.validator`). For a logged-in customer whose active billing or shipping address has `customFields.sw6oidc_placeholder_address`, it adds a blocking `Error` (`sw6oidc-placeholder-address`, with snippets).
- Keep the confirm-page redirect in `PlaceholderAddressSubscriber` as a convenience.
- **Tests:** unit test for the validator; integration test with `/store-api/checkout/order` (400 while flagged).

### R8-M6: clear the flag only when the address is complete
- `PlaceholderAddressSubscriber` (`:215`): after the write, re-read street, city and zipcode (when `country.postcodeRequired`) of the written address ids in one query. Clear the flag only when none of them is `-` or empty.
- **Test:** a write with only `{street}` keeps the flag; a write with street and city clears it.

---

## P6: Passkeys and admin auth

### R8-M8: self-service delete
- `PasskeyCredentialRepository::deleteOwnedByUser()`: drop the `Context` parameter. The ownership-filtered search and the delete run in `Context::createDefaultContext()` with `SYSTEM_SCOPE` (ownership is the authorisation). Check the other self-service paths (`findAllForOwner()` for "My passkeys") for the same ACL dependency.
- **Tests:**
  - A unit test that the repository calls use system scope.
  - An E2E case in `05` with a role user that has only `user.update_profile`: register, then delete a passkey.

### R8-L14: required browser binding
- `AdminLoginNonceService::createNonce()`: drop the `?string $browserBinding = null` parameter; the service computes it through `BrowserBinding::bindCurrentBrowser()`.
- `BrowserBinding::matchesCurrentBrowser(null)` stays true only outside an HTTP request. A null stored hash inside a request is refused.

### R8-L15: counter race
- `PasskeyAuthenticationService`:
  - Remember the stored `sign_count` when the ceremony loads the credential.
  - On `CounterException`, re-read the row. If the response counter is greater than the value remembered at load time, refuse only this assertion (concurrent use). Otherwise disable the key, as today.
  - Applies to admin, storefront and step-up.

### R8-M-3: duplication
- `PasskeyCredentialRepository::userHandle(string $userType, string $userId): string`, used by `StepUpService` and `PasskeyRegistrationService`.
- `Service/Passkey/CeremonyResponse::options(string $sessionId, string $optionsJson): JsonResponse`, used by both passkey controllers and `StepUpController`.

---

## P7: Write guards, data layer, queued side effects

### R8-M7: dry run and queued revocation
- `PasswordSessionRevocationHandler`: before revoking, re-check `PasswordLoginPolicy::isPasswordLoginDisabled($message->userType)`. Do nothing if the policy is off.
- `OidcConfigTransfer` dry run: add the context state `sw6oidc.dry_run`. `Sw6OidcProviderWriteGuardSubscriber::onProviderWritten()` dispatches no message and consumes no confirmation while it is set.
- **Tests:** the handler with the policy off does nothing; a dry-run import dispatches nothing.

### Data layer
| # | Change |
|---|---|
| R8-L21 | Add `Required` to `token_endpoint_auth_method`, `revocation_endpoint_auth_method` and `logout_style`. New unit test: every provider definition field whose column is NOT NULL without a DB default is `Required` (read the column list from the migrations' `CREATE`/`ALTER` statements, or keep a snapshot array in the test). |
| R8-L27 | `Sw6OidcAttributeMappingDefinition::TYPES` (all `TYPE_*`), `Choice(self::TYPES, true)` on `attribute_type`. No migration: check the dev database for unknown types by hand. |
| R8-L28 | Delete the second `PasskeyRpIdConfigValidator` definition (`services.xml:942-946`). |
| R8-L29 | `Sw6Oidc::uninstall()` (without keep-user-data): remove `sw6oidc_*` privileges from `acl_role.privileges` (`JSON_REMOVE` per matching path, or read-filter-write in PHP), and `JSON_REMOVE` `$.sw6oidc_avatar_url_hash`, `$.sw6oidc_avatar_media_id` (P4) and `$.sw6oidc_placeholder_address` from the custom fields. |
| R8-L30 | `Sw6OidcEncryptor`: remove `DEFAULT_PURPOSE`, make `$purpose` required everywhere, and remove `isEncrypted()` (callers use `isEnvelope()`). One static `Sw6OidcEncryptedFieldSerializer::purpose($entity, $column)` used by the write guard and by `CLIENT_SECRET_PURPOSE`. |

### Write guard
| # | Change |
|---|---|
| R8-L22 | `validateEmailVerification()`: overlay the event's `sw6oidc_attribute_mapping` commands (insert, update, delete for this provider) on the stored mappings. |
| R8-L23 | Pass `$rebinding` to `unboundActiveAdminIds()` (`:615`). |
| R8-L24 | Confirmations: `LockoutConfirmationStore`/`IssuerChangeConfirmationStore` get `peek()`. `validate()` peeks, `onProviderWritten()` consumes. |
| R8-L25 | `SsoOnlyInvariant::unboundActiveAdminIds()` and `PasswordSessionRevoker` exclude accounts with an active (not disabled) passkey (D8). |
| R8-L26 | `Sw6OidcCspHostCollector`: `expiresAfter(300)`. |

---

## P8: Health

| # | Change |
|---|---|
| R8-L16 | `HealthCheckController`: `down` answers 200 unless `?strict=1` (D7). README: "not a liveness probe; use `?strict=1` only for SSO-specific monitoring". |
| R8-L17 | `HealthAlertState`: a new state `recovery_pending`. After a healthy probe that follows an alerted outage, stay pending until the webhook accepts the recovery notice. Unit test for the transition table. |
| R8-L18 | Measure first: count PHP sessions created by 100 `GET /sw6oidc/health` calls without cookies in the dev shop. If sessions are created, move health, back-channel and front-channel logout to a route that sets `_routeScope: ['storefront']` with `_stateless: true` (or core's equivalent), and check that `getClientIp()` and the rate limiter still work. |

---

## P9: Maintainability, unused code, docs, release

| # | Change |
|---|---|
| R8-M-1 | Remove the constructor defaults: `Sw6OidcSessionRegistry` (`'P1D'`), `Sw6OidcSessionActivityRecorder` (`?NodeHeartbeat`, `truncateIp`), `HealthCheckController`, `Sw6OidcRateLimiter` limits, `PasskeyAuthenticationService` logger. Wire everything in `services.xml`. `SessionActivityController::seconds()` throws on invalid intervals, like the registry. |
| R8-M-2 | Split `Sw6OidcProviderWriteGuardSubscriber` into validators under `Subscriber/ProviderValidation/` (`UrlValidator`, `SecretValidator`, `NotNullValidator`, `EmailVerificationValidator`, `IssuerChangeValidator`, `SsoOnlyValidator`), each working on a `ProviderWriteState` (stored row + payload + sibling child commands). The subscriber only builds the state and runs the validators. Derive `NOT_NULL_BOOLEANS` from the definition (`BoolField` + `Required`). Split `sw6oidc-provider-detail` into tab components (general, endpoints, behaviour, mappings, access control, health). Do this **after** P7, so the fixes land first and the split is a pure refactor. |
| R8-M-4 | One WebAuthn codec: move it to `src/Resources/app/shared/webauthn-codec.js` and import it from both builds (the admin through a Vite alias, the storefront through a relative import). Rebuild both bundles. |
| R8-M-5 | `sw-skeleton-bar` → `mt-skeleton-bar` (check against the 6.7.15 admin sources first). Add `sw-skeleton-bar` to the CI grep gate. |
| R8-M-U | Remove `ExternalIdentity::$email`, `AccessControlDeniedException::$ruleId` (or use it in logging), `Sw6OidcSession::$createdAt`, the dead branch `AdminOidcGrant.php:156`, the `NodeHeartbeat::recentNodeCount()` parameter, the duplicate one-time-token prune in `SessionActivityCleanupTaskHandler`. Make `hashSessionKey()`, `hashSid()`, `findBindingBySubject()` and `isLegacy()` private. Regenerate `psalm-baseline.xml` and check that it shrinks. |
| Docs | Fix the CLAUDE.md drift listed in the review: `reauth` purpose; JWKS refetch without `kid`; `flow_start` for link and reauth (now true after P2); `recordLogout()` precedence (now true after P3); `OneTimeTokenCleanupTask`; recorder `get()`. Also document the new behaviour from P1–P8. |
| Release | `composer.json` version `0.3.0`, CHANGELOG with a "Breaking" section (PM single migration, D2 trust list, D7 health status). Update the status table in `Code-Review.md`. |

**Done when:** `composer ci` is green, a PR run of every CI job (including `shopware` and `e2e`) is green, and the manual pass below is done.

### Manual pass before merging
- Authelia: SSO login with a secret containing `+` (P2), admin step-up and Storefront re-auth (P2), logout with token revocation (P2/P3), back-channel logout.
- Imitate a customer and try to add a passkey (P1).
- A role admin with only "update own profile": register and delete a passkey (P6).
- A provider editor (not superadmin): try to toggle "revoke superadmin on SSO" (P1).
- Guest checkout, then convert the guest account with SSO-only mode on (P1).
- A headless order with a placeholder address through the Store API (P5).

---

## P10 (optional): Roadmap

From "Future improvements" in `Code-Review.md`, after P0–P9:
- discovery-driven auth-method and PKCE defaults, plus the issuer comparison in the connection test (2);
- `private_key_jwt` and token-error diagnostics (3);
- signed userinfo (4);
- passkey login policy for SSO-bound accounts (9);
- binding the step-up nonce to the token's `jti` (10);
- a per-device registry discriminator (11);
- `jsonSerialize()` without secrets (12);
- `logout_token` size cap and a diagnostics rate limit (13);
- reporting store fallbacks (14);
- the items carried over from revision 7 (15).

Items 1, 5, 6, 7 and 8 are already covered by P1, P4, P5, P7 and P1.
