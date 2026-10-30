# Code Review: `martinkuhl/shopware6-oidc-sso`

| | |
|---|---|
| **Revision** | 8: full re-review of the whole plugin after the revision 7 fix round and the 16 commits since (configurable client authentication, `max_age=0` removal, revocation with an empty body, E2E work). |
| **Review date** | 2026-10-30 (revision 7: 2026-10-07, revision 6: 2026-10-06, revision 5: 2026-10-06, revision 4: 2026-10-05, revision 3: 2026-10-01, revision 2: 2026-09-30, revision 1: 2026-09-29) |
| **Reviewed commit** | `7cb8086` (`main`) |
| **Scope** | Everything under `src/`: PHP, DI config, migrations, admin and storefront JS and Twig. Also `composer.json`, tooling config and the unit tests. |
| **Verified against** | Shopware 6.7.15 core (`vendor/shopware/core`), Symfony 7.4, League OAuth2 9.4, DBAL 4, webauthn-lib 5.3, web-token/jwt-library 4.2 |
| **Reviewer stance** | Harsh on purpose. Assume every finding reaches production unless it is fixed. |

Backend paths are relative to `src/`. Frontend paths are relative to `src/Resources/`. Line numbers are for `7cb8086`.

Older finding texts are in git history: `git show d6b5b35:Code-Review.md` (revision 7), `git show 4d7eb67:Code-Review.md` (revision 6).

Every finding was traced in the code. **PLAUSIBLE** marks findings whose impact depends on IdP behaviour, configuration or runtime environment; everything else is confirmed.

---

## Summary

### Verdict

**Not release-ready.** Revision 7 reported nothing above Low. This full re-review found **2 High** and **10 Medium** findings that the earlier rounds missed:
- Both Highs break a trust boundary the plugin claims to enforce:
  - **R8-H1:** a non-superadmin provider editor can demote superadmins and switch off Administration password login.
  - **R8-H2:** an admin who imitates a customer can attach a permanent passkey or SSO identity to that customer.
- The Mediums are real functional bugs: SSO logins fail with common secrets, admins lose their roles when the groups claim is missing, and logout acts on the wrong session.

One unit test fails (see Tooling): a timezone bug in the test, not in the code.

### Numbers

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| New in revision 8 | 0 | 2 | 10 | 32 |
| Still open from revision 7 | 0 | 0 | 0 | 2 partial (R3-L29, now sharpened as R8-L10; R3-L49) |

### Tooling (run on `7cb8086`, PHP 8.3, `TZ=Europe/Berlin`)

| Tool | Result |
|---|---|
| PHPUnit (unit) | **1 failure** in 876 tests (2301 assertions): `SessionActivityCleanupTaskHandlerTest::testDeletesActivityOlderThanTheRetentionInBatches`, see R8-L31 |
| PHPCS | clean |
| PHPStan level 8 `src/`, level 5 `tests/` | no errors |
| Psalm (errorLevel 4, `findUnusedCode`) | no errors. The baseline hides two unused DTO properties (R8-M-U). |
| Rector (dry-run) | clean |
| Integration / E2E | not run locally (no Docker shop plus Dex in this environment). The recent commits are E2E fixes, so check the latest CI run of `main`. |

---

## High

### R8-H1: Superadmin-affecting provider flags are not trust fields
- **Where:** `Subscriber/ProviderTrustGuardSubscriber.php:45-65` (`TRUST_FIELDS`). Admin UI: `app/administration/src/module/sw6oidc-provider/page/sw6oidc-provider-detail/sw6oidc-provider-detail.html.twig` (the switches use `:disabled="!canEdit"`, not `canEditTrust`).
- **What's wrong:** `revoke_superadmin_on_sso`, `sync_admin_role_on_sso` and `disable_non_oidc_admin_login` are missing from `TRUST_FIELDS`. A user with only the `sw6oidc_provider` editor role can change them. `AdminProvisioningService::syncRole()` (`:354`) removes superadmin whenever both sync flags are on. R3-H4 exists to stop exactly this.
- **Failure scenario:** An editor turns on "sync admin role" and "revoke superadmin on SSO" on the admin provider. On their next SSO login, every superadmin without a superadmin group mapping is demoted (except the last one). Separately, the same editor can switch Administration password login off for everyone and confirm the lockout prompt themselves.
- **Fix:** Add the three columns to `TRUST_FIELDS` and use `canEditTrust` in the UI. Better, invert the model: keep an allow-list of fields a non-superadmin editor *may* change, and treat every other column as a trust field. The new `token_endpoint_auth_method` and `revocation_endpoint_auth_method` columns are unprotected today for the same reason.

### R8-H2: Customer imitation counts as fresh authentication, which allows a persistent backdoor
- **Where:** `Subscriber/CustomerAuthenticationClockSubscriber.php:24-27`, `Service/Session/SessionAuthenticationClock.php:31,40`.
- **What's wrong:** Core's `ImitateCustomerRoute::imitateCustomerLogin()` calls `AccountService::loginById()` (`vendor/.../ImitateCustomerRoute.php:107`), which dispatches `CustomerLoginEvent`. The subscriber stamps the session as freshly authenticated without checking `SalesChannelContext::getImitatingUserId()`, and `isFresh()` doesn't check it either.
- **Failure scenario:**
  1. An admin with the imitate-customer privilege opens a customer's Storefront session.
  2. Within 600 s they register **their own** passkey (`/sw6oidc/passkey/registration-*`), or `POST /sw6oidc/link` their own IdP account.
  3. They now have permanent, passwordless access to the customer account. It survives losing the privilege or leaving the company, and it bypasses the imitation token's expiry and audit trail.

  This is exactly what R3-M5 and H7 say a session alone must not allow.
- **Fix:**
  - Don't stamp when `getImitatingUserId() !== null`.
  - Make `isFresh()` return false while imitating.
  - Refuse passkey registration, SSO linking and re-auth outright in an imitated context.
  - Test with a context that has an imitating user.

---

## Medium

### R8-M1: `client_secret_basic` credentials are not form-urlencoded
- **Where:** `Service/Http/OidcHttpClient.php:81` (built from `Service/Oidc/ClientAuthentication.php:42`).
- **What's wrong:** RFC 6749 §2.3.1 requires client_id and secret to be `application/x-www-form-urlencoded` before base64. The code base64-encodes the raw `id:secret`. Basic is the default method, and the token exchange and revocation both use it.
- **Failure scenario:** Authelia (fosite) and Keycloak URL-decode both parts. A secret containing `+` (any base64-style secret) arrives with a space instead, the token endpoint answers `invalid_client`, and every SSO login fails with a generic "login failed". A `%` in the secret fails to decode. A `:` in the client_id breaks the split everywhere.
- **Fix:** `base64_encode(rawurlencode($id) . ':' . rawurlencode($secret))`, built in `ClientAuthentication` and not in the HTTP client. Unit test with `a+b%2F:c`.

### R8-M2: moved to Low, see R8-L32
After discussion this is not a Medium:
- Failing closed without `auth_time` is intended and documented.
- Dropping `max_age=0` (`2dabbd4`) was the right fix for Authelia 4.39.

What remains is an interop improvement plus the Storefront error handling.

### R8-M3: A missing groups claim strips every managed admin role
- **Where:** `Service/Provisioning/AdminProvisioningService.php:322-356`, via `Service/Oidc/ClaimsNormalizer.php:130-137`.
- **What's wrong:** `normalizeGroups(null)` returns `[]`, so `syncRole()` treats "IdP sent no groups" as "user is in no groups". It removes every role it granted earlier, and with `revoke_superadmin_on_sso` also superadmin. N-M10 fixed this exact case (group overage) for access-control rules, but not for role sync.
- **Failure scenario:** Entra ID with more than 200 groups sends `_claim_names.groups` in place of `groups`. A userinfo hiccup or a dropped scope has the same effect. On the next login every SSO admin loses all mapped ACL roles, or superadmin.
- **Fix:** Carry a `groupsClaimPresent` flag on `MappedProfile`. Skip role sync and customer-group sync when the configured `group_attribute` is absent or listed in `_claim_names`.

### R8-M4: An unknown locale claim resets the admin's locale on every login
- **Where:** `Service/Provisioning/AdminProvisioningService.php:413-415` with `:551-578`. The same pattern is in `CustomerProvisioningService.php:578` (`resolveSalutationId()` on sync).
- **What's wrong:** `syncProfile()` uses `resolveLocaleId()`, which falls back to en-GB (or the first locale) when the claim doesn't exactly match a `Locale.code`.
- **Failure scenario:** Keycloak and Google send `locale: "de"`, but Shopware's code is `de-DE`. With `sync_admin_profile_on_sso` on, every German admin's Administration flips back to English on every login, overwriting their own choice.
- **Fix:** On sync, write `localeId` only on a real match. Normalise `_` to `-` and try a language-prefix match. Use the fallback on create only. Do the same for salutation.

### R8-M5: Placeholder addresses can reach orders outside the Storefront confirm page
- **Where:** `Storefront/EventSubscriber/PlaceholderAddressSubscriber.php:167-204`.
- **What's wrong:** Only `frontend.checkout.confirm.page` is guarded. Store API checkout (`/store-api/checkout/order`), headless frontends, express-checkout plugins and a direct POST to `frontend.checkout.finish.order` all bypass it. CLAUDE.md says placeholders "must never reach an order".
- **Failure scenario:** A JIT-created customer on a headless shop orders to `street: "-"`, `city: "-"`.
- **Fix:** Add a `CartValidatorInterface` that puts a blocking cart `Error` on flagged addresses. That covers both the Storefront and the Store API. Keep the redirect as a convenience.

### R8-M6: The placeholder flag is cleared when only one field is real
- **Where:** `Storefront/EventSubscriber/PlaceholderAddressSubscriber.php:215`.
- **What's wrong:** The flag goes as soon as `street` *or* `city` is written with a non-placeholder value.
- **Failure scenario:** Address sync (partial by design) writes only a mapped street, or an Admin API PATCH sends just `{street}`. The flag is gone, `city` stays `-`, and the checkout guard no longer fires.
- **Fix:** After the write, re-check the stored row in SQL (street, city, and zipcode where the country requires it). Clear the flag only when no `-` remains.

### R8-M7: A dry-run import, or a policy flip-back, can still end real sessions
- **Where:** `Service/Config/OidcConfigTransfer.php:129-150`, `Subscriber/Sw6OidcProviderWriteGuardSubscriber.php:288-300`, `Service/Security/Message/PasswordSessionRevocationHandler.php:16-23`.
- **What's wrong:** `--dry-run` rolls the transaction back, but `provider.written` has already dispatched `PasswordSessionRevocationMessage`. The handler revokes unconditionally and never re-checks whether the policy is still on.
- **Failure scenario:**
  - With a non-DB messenger transport (Redis or AMQP, recommended for production), a dry-run import of a file with `disableNonOidcAdminLogin: true` leaves a queued message. The worker then ends every password session of unbound admins.
  - The same happens when an admin turns SSO-only on and off again within the queue latency.
- **Fix:**
  - In the handler, re-check `PasswordLoginPolicy::isPasswordLoginDisabled($userType)` before revoking.
  - Mark dry-run writes with a context state that suppresses the guard's side effects.
  - Dispatch the message after the outer transaction commits, not on `written`.

### R8-M8: A non-superadmin admin can't delete their own passkey
- **Where:** `Controller/Api/PasskeyAdminController.php:181` calls `Service/Passkey/PasskeyCredentialRepository.php:210-224` (`deleteOwnedByUser()`).
- **What's wrong:** The DAL `search()` and `delete()` run with the request's `AdminApiSource` context. Core's ACL validator then requires `sw6oidc_passkey_credential:read`/`:delete`, the recovery-grid privileges. The "My passkeys" tab needs only `user.update_profile`. Registration works only because it writes in system scope.
- **Failure scenario:** An "Editor" admin loses the device that holds their passkey and clicks delete. They get a 403, and the key stays usable. That is the case R3-M6 was built for. E2E 05 uses a privileged admin, so tests don't catch it.
- **Fix:** Keep the ownership filter, and run search and delete in `Context::SYSTEM_SCOPE`. Do the same for every other self-service write (future nickname edits). Add an integration test with a role user.

### R8-M9: Repeat customer logins duplicate registry entries, and logout acts on the oldest one
- **Where:** `Service/Session/Sw6OidcSessionRegistry.php:139-146, 272` (`ORDER BY created_at ASC` plus `[0]`), `Storefront/Service/OidcLogoutRoute.php:198`, `Storefront/Controller/OidcCallbackController.php:150`, `Service/Session/Sw6OidcSessionActivityRecorder.php:110`.
- **What's wrong:** While the customer's context is alive, `AccountService::loginById()` → `CartRestorer::restore()` returns the *existing* context token. So each further OIDC login (second device, re-login) registers another row with the same `session_key_hash`. Nothing deduplicates them, and `findBySessionKey()` returns the oldest row.
- **Failure scenario:** A customer logs in via SSO on the phone (entry A: sid1, RT1), then on a laptop (entry B: same token, sid2, RT2), then logs out on the laptop.
  - Entry A is removed and RT1 (the phone's) is revoked.
  - `id_token_hint` carries sid1.
  - RT2 is never revoked, and entry B remains. On a shared PC the IdP session may survive (PLAUSIBLE: depends on whether the IdP acts on the hint's `sid`).
  - `recordLogout()` (`registryId OR sessionKeyHash`, newest first) closes B's activity row, not A's.
  - A later back-channel logout for sid2 finds the stale entry B, takes the R3-L30 fallback and ends every session of that customer.
- **Fix:**
  - In `register()`, supersede existing customer entries with the same hash, and revoke their tokens.
  - At logout, take all entries for the hash, remove them and revoke each one's tokens.
  - In `recordLogout()`, match the exact `registrySessionId` first.

### R8-M10: Back-channel logout acts only for the first provider that matches iss and aud
- **Where:** `Controller/Oidc/BackChannelLogoutController.php:155-168`, `Service/Provider/ProviderResolver.php:62-76`.
- **What's wrong:** Nothing stops two active providers from sharing an issuer and client_id (for example separate `customer` and `admin` rows for one IdP client). `findByIssuer()` is unsorted, `resolveProvider()` takes the first match, and registry lookups are scoped by provider id. The front-channel controller iterates every matching provider; the back-channel controller does not.
- **Failure scenario:** The IdP posts a logout token for a session created through provider #2. Provider #1 is chosen, no session is found, and the answer is 200. The session survives the IdP logout, and the IdP never retries.
- **Fix:** Verify against one matching provider, then call `logout()` for every provider with the same issuer and a client id in `aud`. Or enforce a unique (issuer, client_id) pair in the write guard.

### R8-M11: Guest-to-customer conversion bypasses Storefront SSO-only mode
- **Where:** `Resources/config/services.xml:704-720` (only `LoginRoute`, `RegisterRoute` and `RegisterConfirmRoute` are decorated).
- **What's wrong:** Core's `ConvertGuestRoute` (`/store-api/account/convert-guest`, also used by the Storefront `AuthController::convertGuest`) sets `guest=false` and a password on the logged-in guest.
- **Failure scenario:** With `disable_non_oidc_customer_login` on, a visitor checks out as a guest (allowed), converts the account, and now has a password account with a live session. The "no registration" rule is bypassed.
- **Fix:** Decorate `AbstractConvertGuestRoute` with the same `PasswordLoginPolicy` check. Add it to the CLAUDE.md enforcement list and to the E2E suite.

---

## Low

### Protocol and HTTP
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L1 | `Service/Http/OidcHttpClient.php:61` | `postFormIgnoringResponseBody()` throws only on `>= 400`, and redirects are disabled. A 301/302 from the revocation endpoint (http→https, or a proxy sending unauthenticated requests to a login portal) counts as success. Nothing is revoked, and only a debug line is logged. | Require 2xx, and log anything else at warning level. |
| R8-L2 | `Service/Oidc/TokenExchangeService.php:59-76`, `Service/Oidc/RpInitiatedLogoutService.php:92-99` | `ClientAuthentication` claims "one place so the two calls can't drift", but each caller resolves the secret itself. For a confidential client with an *empty* secret, the token exchange sends `Basic base64("id:")` while revocation skips. The envelope check exists only in the token exchange. | Resolve the secret in `ClientAuthentication::forProvider()` and throw `ClientSecretUnavailableException` for both. Revocation catches it and skips. |
| R8-L3 | `Storefront/Controller/SendAuthorizationRequestController.php:110` (`link`), `:153` (`reauth`) | Neither consumes `SCOPE_FLOW_START`; only `login()` (`:57`) does. A logged-in customer can loop `/sw6oidc/reauth` and write unlimited 600 s flow entries. The admin counterparts are limited per admin. | Consume `SCOPE_FLOW_START . ':' . $customerId`, as the admin side does. |
| R8-L32 | `Service/AdminAuth/StepUpService.php:80`, `Storefront/Controller/SendAuthorizationRequestController.php:172`, `Storefront/Controller/OidcCallbackController.php` (generic `\Throwable` branch) | Step-up and re-auth fail closed without `auth_time`. That is intended: without it there is no proof of a fresh login, and dropping `max_age=0` was the right fix for Authelia. Two things are left. (1) Nothing *asks* for `auth_time`, so IdPs that send it only on request can't use OIDC step-up, although they could (OIDC Core §2 and §5.5). (2) On the Storefront a failed freshness check lands in the generic branch: the customer sees "login failed", and `recordFailure()` counts it against the callback budget. | Send `claims={"id_token":{"auth_time":{"essential":true}}}` only when discovery advertises `claims_parameter_supported`. That changes nothing for Authelia, which sends `auth_time` anyway; test once against it. Don't use a positive `max_age`: its Authelia behaviour isn't verified. Catch the freshness failure separately, with its own message, and don't count it. Dex stays passkey-only, as documented. |
| R8-L4 | `Service/Oidc/ClaimsMerger.php:41-45` | `sub`, `email` and `email_verified` are each taken from the id_token separately. An id_token with `email` but no `email_verified` gets userinfo's `email_verified: true` attached to the id_token's email. (PLAUSIBLE: needs an inconsistent IdP.) | Take `email` and `email_verified` as a pair from whichever source supplies `email`. |

### Identity and provisioning
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L5 | `Controller/Api/OidcUserProviderAdminController.php:114-135` | `user:update` plus `user-verified` is enough to unlink **any** admin, a superadmin included (only the last SSO admin is protected). The target's sessions and registry entries stay alive. (PLAUSIBLE: depends on what core lets `user:update` do to superadmins.) | Require a superadmin to unlink a superadmin. End the target's sessions on unlink. |
| R8-L6 | `Service/Provisioning/AdminProvisioningService.php:465-492`, `AvatarFetcher.php:272` | When the picture URL changes, `saveMediaFile(..., $existingAvatarId)` overwrites whatever media is the current avatar, even one chosen by hand or shared. Pixel dimensions are not capped: a 2 MB, 30k×30k PNG passes and can exhaust the thumbnail worker. (PLAUSIBLE) | Store the plugin's own media id in `customFields` and replace only that one. Reject images over about 4096 px per side. |
| R8-L7 | `Service/Security/Sw6OidcAccessControlEvaluator.php:100,146` | `email_domain` ignores `email_verified`, so with `require_email_verified` off a self-registered `x@corp.com` passes. IDN domains always fail `FILTER_VALIDATE_EMAIL`. | Require a verified email for this operator, and compare punycode-encoded domains. |
| R8-L8 | `Service/Oidc/ClaimsNormalizer.php:132` vs `Sw6OidcAccessControlEvaluator.php:141` | For `groups: "staff admins"`, the access rule `contains admins` passes (it splits on whitespace and commas), but role mapping sees one group `"staff admins"`. The two disagree without telling anyone. | Use one tokenisation for both, and document it. |
| R8-L9 | `Service/Provisioning/CountryResolver.php:81-103` | The country lookup ignores `active` and sales-channel assignment, so a user-editable claim can resolve to a country that checkout rejects. | Filter `active = 1`, and prefer the channel's countries. |
| R8-L10 | `CustomerProvisioningService.php:99-101` vs `AdminProvisioningService.php:95` (R3-L29, sharpened) | The duplication now changes behaviour. The admin path refuses an inactive account *before* syncing. The customer path syncs profile, group and addresses into a deactivated account, then fails in `loginById()` with a generic `CustomerNotFoundByIdException`, not an account-policy error. The create/bind/winner `catch` blocks (`Customer:113-135`, `Admin:123-146`) are copy-pasted. The fallback names differ: `?: '-'` turns a local part of `"0"` into `-`. "Skip unchanged values" is written twice (`withoutUnchanged()` vs `Admin:431-435`). | Extract one inactive-account gate, a `JitAccountCreator::createAndBind()`, and a shared profile-diff helper. |
| R8-L11 | `Service/Config/OidcConfigTransfer.php:135,144` | Import failures are keyed by `appName`, so two providers with the same name overwrite each other's error. A non-scalar `appName` is cast outside the inner `try`, which aborts the run after earlier providers have committed. | Key by index or id, and validate `appName` inside the `try`. |
| R8-L12 | `Service/Provisioning/UserProviderBindingService.php:305-315` | A unique violation on the *subject* key re-reads by `userId`, finds nothing and throws `ProviderMismatchException`, not `SubjectAlreadyLinkedException`. Explicit linking shows the wrong error. | Re-read by subject on that key and throw the matching exception. |

### Passkeys and admin auth
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L13 | `Storefront/Controller/AccountPasskeyController.php:84`, `PasskeyController.php:282` | The `sw6oidc_login_credential_id` session marker survives logout (core's default `invalidateSessionOnLogOut=false`). Log in with passkey X, log out, log in with a password, delete X: the password session is logged out. The marker is also redundant now that `PasskeySessionTerminator` (R3-M6) exists. | Drop the marker. Log out only if the current context token is among those the terminator ended. |
| R8-L14 | `Service/AdminAuth/AdminLoginNonceService.php:32`, `Service/Security/BrowserBinding.php:62-64` | `createNonce(..., ?string $browserBinding = null)` defaults to null, and `matchesCurrentBrowser(null)` returns true. A future caller that omits the argument silently disables M1 login-CSRF protection, and no test notices. (PLAUSIBLE: no current caller passes null.) | Make the parameter required, or compute it inside the service. |
| R8-L15 | `Service/Passkey/PasskeyAuthenticationService.php:159-160`, `PasskeyCredentialRepository.php:120` | Two concurrent assertions (counters 5 and 6) processed out of order: the second one throws `CounterException`, and the key is disabled as cloned. (PLAUSIBLE) | On `CounterException`, re-read the row. Disable only if the counter is ≤ the value read *before* the ceremony started; otherwise just refuse this assertion. |

### Sessions, health, state
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L16 | `Controller/HealthCheckController.php:225, 263-268` | With one monitored provider, an IdP outage is `down`, which answers 503. A load balancer pointed at this URL pulls the whole shop, guest checkout included, out of rotation. (PLAUSIBLE: operational) | Answer 200 with `status: down` by default, and make 503 opt-in. Document that it is not a liveness probe. |
| R8-L17 | `Service/Health/HealthAlertState.php:48-51`, `ProviderHealthMonitor.php:145-149` | A recovery notice the webhook rejects is never retried: the state is already `ok`. The class doc promises retries. | Keep a `recoveryPending` state until the notice is delivered. |
| R8-L18 | `Controller/HealthCheckController.php:173`, back- and front-channel controllers | The storefront route scope bootstraps a session and sales-channel context for every cookie-less machine call. A 10 s monitor creates about 8.6k throwaway sessions per day. (PLAUSIBLE) | Use a lightweight scope, or skip the session for these routes. |
| R8-L19 | `Service/Cache/RedisAtomicCache.php:348-356` | The backend is resolved once per instance, with no `kernel.reset`. A long-running worker (messenger, FrankenPHP/RoadRunner) stays on the DB fallback forever if Redis was down at first use. If Redis dies later, every call pays the 1.5 s timeout and the down marker is never consulted. (PLAUSIBLE) | Tag the service `kernel.reset` and clear `resolved`. Call `markDown()` on command errors too. |
| R8-L20 | `Service/Session/Sw6OidcSessionRegistry.php:211-248` | `prune()` runs three unbounded DELETEs with correlated `NOT EXISTS`. The other cleanups are batched with a time budget. Together with R8-M9 (table growth), this is one long lock on `sw6oidc_session` while logins insert. | Batch with `LIMIT`, as `DatabaseAtomicCache::prune()` does. |

### Data layer and write guards
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L21 | `Core/Content/Provider/Sw6OidcProviderDefinition.php:116,119,122` | `token_endpoint_auth_method`, `revocation_endpoint_auth_method` and `logout_style` are NOT NULL columns without `Required`. `""` becomes null, `Choice` is skipped for null, and `PATCH {tokenEndpointAuthMethod: ""}` returns a DBAL 500. Same class of bug as R3-L43. | Add `Required` (the defaults cover inserts). Add a test that every NOT NULL column without a DB default is `Required`. |
| R8-L22 | `Subscriber/Sw6OidcProviderWriteGuardSubscriber.php:439-465` | `validateEmailVerification` reads only the *stored* email mappings. Changing the mapping and turning on "require verified email" in one save is refused with `SW6OIDC_EMAIL_TRANSFORM_UNVERIFIABLE`. | Overlay the event's `sw6oidc_attribute_mapping` commands on the stored rows. |
| R8-L23 | `Subscriber/Sw6OidcProviderWriteGuardSubscriber.php:615` | `unboundActiveAdminIds($changes)` is called without `$rebinding`, although `adminAccessPossible` (`:603`) gets it. An issuer change with rebind plus SSO-only in one save shows a false lockout prompt with an inflated count. | Pass `$rebinding`. |
| R8-L24 | `Subscriber/Sw6OidcProviderWriteGuardSubscriber.php:529-540, 695-721` | The issuer-change and lockout confirmations are consumed inside `validate()`, even when another violation then rejects the write. The admin confirms, fixes the unrelated error, and is asked to confirm again. | Peek during validation and consume in `onProviderWritten`. |
| R8-L25 | `Service/Security/PasswordSessionRevoker.php`, `SsoOnlyInvariant::unboundActiveAdminIds` | Passkey-only accounts count as "unbound": their sessions are revoked, and they are counted as locked out in the prompt, although passkey login keeps working. | Exclude accounts with an active passkey, or document it. |
| R8-L26 | `Service/Security/Sw6OidcCspHostCollector.php:65-66` | The CSP host list in `cache.app` has no TTL, and invalidation runs only on the node that handled the write. With per-node caches, other nodes keep old IdP origins until `cache:clear`. (PLAUSIBLE) | `expiresAfter(300)`. |
| R8-L27 | `Core/Content/AttributeMapping/Sw6OidcAttributeMappingDefinition.php:69` | `attribute_type` has no `Choice`, although the 22 `TYPE_*` constants exist. A typo (`Email`, `first_name`) is stored and silently ignored. | Add `TYPES` and `Choice(…, true)`. |
| R8-L28 | `Resources/config/services.xml:629-633` and `:942-946` | `PasskeyRpIdConfigValidator` is defined twice, and the second silently overrides the first. | Delete one. |
| R8-L29 | `Sw6Oidc.php:27-48` | Uninstall without "keep user data" leaves `sw6oidc_*` entries in `acl_role.privileges`, and the custom-field keys `user.custom_fields.sw6oidc_avatar_url_hash` and `customer_address.custom_fields.sw6oidc_placeholder_address`. | Strip them with `JSON_REMOVE` and a filter on the privileges. |
| R8-L30 | `Service/Security/Sw6OidcEncryptor.php:37, 68-136` | `DEFAULT_PURPOSE = 'default'` is a default parameter on `encrypt`/`decrypt`/`decryptOrNull`/`canDecrypt`, which undermines N-L4: a new caller that forgets the purpose shares a key. The purpose string is built in three places (serializer `purpose()`, write guard `:317`, `CLIENT_SECRET_PURPOSE`). `isEncrypted()` duplicates the static `isEnvelope()`. | Make the purpose required, use one builder, and drop `isEncrypted()`. |

### Tests
| # | Where | What's wrong | Fix |
|---|---|---|---|
| R8-L31 | `tests/Unit/ScheduledTask/SessionActivityCleanupTaskHandlerTest.php:35-36` | The test compares the handler's UTC `-30 days` with a *local-time* `strtotime('-30 days')`. In `Europe/Berlin` across the DST change (25 Oct), they differ by 3600 s and the test fails. CI passes only because it runs in UTC. | `new \DateTimeImmutable('-30 days', new \DateTimeZone('UTC'))`, or set `date.timezone=UTC` in `phpunit.xml.dist`. |

---

## Maintainability, conventions and unused code

| # | Severity | Where | What's wrong | Fix |
|---|---|---|---|---|
| R8-M-1 | Low | `Sw6OidcSessionRegistry:49` (`'P1D'`), `Sw6OidcSessionActivityRecorder:40-42` (`?NodeHeartbeat = null`, `truncateIp = false`), `HealthCheckController:191-193`, `Sw6OidcRateLimiter` limits, `PasskeyAuthenticationService:51` (`?LoggerInterface = null`) | Constructor defaults that hide misconfiguration are still there. Revision 7 said the last of these were gone. A missing logger silently hides clone-detection warnings. `SessionActivityController::seconds()` falls back silently on an invalid interval, while the registry throws on the same parameter. | Make them required and wired in DI. Handle invalid intervals the same way everywhere. |
| R8-M-2 | Low | `Subscriber/Sw6OidcProviderWriteGuardSubscriber.php` (783 lines), `sw6oidc-provider-detail` (960 JS + 1144 Twig lines) | The write guard mixes about 8 concerns: SSRF, redirect URLs, not-null, secret, customer lockout, email verification, issuer rebind, SSO-only and revocation. R8-L22 and R8-L23 come from this. `NOT_NULL_BOOLEANS` is a hand-kept list that has already drifted (R8-L21). | Split it into small validators over one "provider row after this write" model (stored row + payload + child commands). Split the detail page into tab components. |
| R8-M-3 | Low | `StepUpService.php:184`, `PasskeyRegistrationService.php:127,141` | The user handle `hash('sha256', "$type:$id", true)` is written three times. The `['sessionId' => …, 'options' => json_decode(…)]` response shaping is repeated five times across the two passkey controllers and `StepUpController`. | One static `userHandle()` helper and one response helper. A first step towards the roadmap's shared ceremony service. |
| R8-M-4 | Low | `app/administration/src/service/webauthn-codec.js` (176 lines), `app/storefront/src/.../webauthn-codec.js` (179 lines) | Two almost identical WebAuthn codecs. | One source module imported by both builds. |
| R8-M-5 | Low | `component/sw6oidc-user-provider-info/sw6oidc-user-provider-info.html.twig:4` | Uses `<sw-skeleton-bar>`. The Meteor replacement is `mt-skeleton-bar`, and the CI deprecation grep doesn't cover it. (PLAUSIBLE: not checked against the 6.7.15 admin sources) | Migrate it, and extend the grep gate. |
| R8-M-U | Low | Unused code (each candidate grepped across PHP, XML, Twig and JS) | Unused: `ExternalIdentity::$email` (assigned, never read; hidden by the Psalm baseline); `AccessControlDeniedException::$ruleId` (only used in its own message; baselined); `Sw6OidcSession::$createdAt` (hydrated, never read). Dead branch: `AdminOidcGrant.php:156` `$userId === ''` (impossible after `Uuid::isValid()`). `public` but used only inside their own class: `Sw6OidcSessionRegistry::hashSessionKey()`, `Sw6OidcSessionActivityRecorder::hashSid()`, `UserProviderBindingService::findBindingBySubject()`, `Sw6OidcEncryptor::isLegacy()`. Never passed by any caller: `NodeHeartbeat::recentNodeCount($windowSeconds)` and the `Sw6OidcRateLimiter` limit and interval parameters. The duplicate prune: `SessionActivityCleanupTaskHandler` also calls `oneTimeTokens->prune()`, which the hourly task already does. | Remove them, or make them private. Shrink the Psalm baseline so it stops hiding real dead code. |

**CLAUDE.md drift (Low):**
- The flow purposes are listed as `login|link|step_up`; `reauth` is missing.
- It says the JWKS refetch happens "only when the kid is missing", but a login token *without* a `kid` also refetches on failure (`JwtVerifier.php:213`).
- It says "Flow start consumes the flow_start budget", which is false for the Storefront link and reauth (R8-L3).
- `recordLogout()` is described as "registry id, else hash, optionally newest open row". The code does `registryId OR hash` with no precedence and no newest-row fallback.
- `OneTimeTokenCleanupTask` is missing from the `ScheduledTask/` list.
- "Every method swallows its own errors": `get()` doesn't.

**Checked and clean** (no finding): the state, PKCE, nonce and browser binding; `RelayStateValidator`; `JwtVerifier` (algorithm allow-list, `crit`, `kid` cap, `azp`, refetch cooldowns); the League bridge (scope stripping, step-up TTL, inactive users); WebAuthn validation (exact origins, `rpIdHash`, UV, purpose binding, counter checked after the signature); the atomic store (`FOR UPDATE` + delete, `addIfAbsent`, Redis error vs. miss); the back-channel `jti` replay TTL; the rate-limiter peek; the post-logout landing (no open redirect); the encryption envelopes; migration 21 (idempotent, MariaDB-safe); XSS (no `v-html`, `|raw` or `innerHTML`; every `postMessage` listener checks origin and source); snippets (en-GB and de-DE in sync, none unused); write-guard coverage of clone, upsert and Sync API; account linking (bindings are keyed on subject plus issuer, and the mapped email must equal the IdP's `email` claim before `email_verified` counts).

---

## Still open from revision 7

| # | Status | What is left |
|---|---|---|
| R3-L29 | partial, **now with a behaviour difference** | See R8-L10. |
| R3-L49 | partial | The bridge still depends on core OAuth internals (`FakeCryptKey`, core repositories), pinned by `CoreOAuthContractTest`. Shopware has no public API for this. |
| R3-L48 | won't fix (decided) | `TestResultTranslator` reads the snippet JSON. |

---

## Future improvements (after the fixes)

1. **Trust model: deny by default.** Keep an allow-list of provider fields an editor may change, so every new column needs a superadmin until someone decides otherwise (prevents the next R8-H1).
2. **Discovery-driven defaults:**
   - Read `token_endpoint_auth_methods_supported`, `revocation_endpoint_auth_methods_supported` and `code_challenge_methods_supported`. Preselect the method, or warn when the configured one isn't advertised.
   - Pass the auth method into the connection test.
   - Compare the discovered `issuer` with the configured one (Discovery §4.3). A trailing-slash mismatch today passes every check and fails at the first login.
3. **Client authentication:** add `private_key_jwt` as a third `ClientAuthentication` method. Keep a capped `error`/`error_description` from 4xx token responses so admins can diagnose `invalid_client`. Validate `token_type`.
4. **Signed userinfo:** accept `application/jwt` userinfo responses, verified through `JwtVerifier`.
5. **Group-driven sync with a `groupsClaimPresent` flag**, and a `LocaleResolver` (`de` → `de-DE`, `de_DE`) shared by admins and customers.
6. **One `CartValidator`** for placeholder and incomplete addresses, replacing the confirm-page redirect.
7. **Side-effect-free dry runs**, and queued work that re-checks its precondition when it runs.
8. **Imitation-aware Storefront:** exclude imitated contexts from every sensitive action, and from passkey-login activity attribution.
9. **Passkeys vs. IdP offboarding:** an optional policy "a passkey login by an SSO-bound account requires an active binding to an active provider". Today a passkey bypasses IdP-side deprovisioning and access rules.
10. **Bind the step-up nonce to the requesting token's `jti`**, not just the user id.
11. **Registry per device:** deduplicate per context token, and store a per-device discriminator so a customer logout can target one IdP session.
12. **`Sw6OidcProviderEntity::jsonSerialize()`** that drops `clientSecret` and `healthAlertWebhookUrl`. The hydrated entity holds them in plaintext, so any future `JsonResponse($provider)` or log dump would leak them.
13. **Cap `logout_token` size** (for example 16 KB) before `decodeUnverified()`, and rate-limit the diagnostics live probe.
14. **Report store fallbacks:** count Redis-to-database fallbacks and show them in diagnostics.
15. Items carried over from revision 7: passkey conditional mediation, `PasskeyCredentialDeletedEvent`, a clone-detection Flow trigger, a bounded HTTP layer (response-size caps, separate client for user content), enforcing `S256` unless discovery lacks it, checking `typ: logout+jwt`, a `Configuration` tree for the `SW6OIDC_*` env vars, a small pre-auth admin bundle, and showing the `PublicError` reference in toasts.

---

## Suggested fix order

1. **R8-H1, R8-H2.** Trust boundaries; small, contained fixes with unit tests.
2. **R8-M1.** It breaks logins with secrets that contain `+` or `%`.
3. **R8-M3, R8-M7, R8-M9, R8-M10, R8-M11.** Lost roles, wrongly ended sessions, sessions that survive logout, SSO-only bypass.
4. **R8-M8, R8-M4, R8-M5, R8-M6.** Admin self-service and Storefront data quality.
5. R8-L31 (make the suite timezone-proof), then the Lows grouped by area, then the maintainability rows.
6. A green CI run on the fix branch, including integration and E2E, plus a role-user E2E case for the passkey tab (R8-M8) and an imitation case (R8-H2).
