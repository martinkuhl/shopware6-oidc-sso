# Code Review: `martinkuhl/shopware6-oidc-sso`

| | |
|---|---|
| **Revision** | 7: fix round for every finding still open in revision 6. Fixed findings are listed once in the status table, with no detail text. What remains open is at the end. |
| **Review date** | 2026-10-07 (revision 6: 2026-10-06, revision 5: 2026-10-06, revision 4: 2026-10-05, revision 3: 2026-10-01, revision 2: 2026-09-30, revision 1: 2026-09-29) |
| **Reviewed commit** | `a9577b4` plus the documentation commit on `fix/code-review-rev2` |
| **Scope** | Everything under `src/`: PHP, DI config, migrations, admin and storefront JS and Twig. Also `composer.json`, CI and tooling config, the committed bundles. |
| **Verified against** | Shopware 6.7 core and administration, Symfony 7.4, League OAuth2 9.4, DBAL 4, webauthn-lib 5.3, web-token/jwt-library 4 |
| **Reviewer stance** | Harsh on purpose. Assume every finding reaches production unless it is fixed. |

Backend paths are relative to `src/`. Frontend paths are relative to `src/Resources/`.

The finding texts from revision 6 and earlier are in git history:
- `git show 4d7eb67:Code-Review.md` has revision 6, with every finding fixed here.
- `git show f8c1195:Code-Review.md` has the revision 5 status table.

---

## Summary

### Verdict

**No Critical, High or Medium finding is open. Every Low from revision 6 is either fixed or closed by a recorded decision.**

The fix round found one new High: **R7-H1**, a Storefront passkey page that crashed. It was found by the new `lint:container` CI step and fixed in the same round.

**The release gate is still not met.** The integration and E2E suites have **not been run** against this fix round, because no Docker shop plus Dex was available. CI now runs both as blocking jobs, and there is a new admin smoke spec. A green CI run on this branch is the last open gate.

### Fixed in this round

| Commit | Fixed |
|---|---|
| `af243ae` (Q5) | **OIDC protocol, HTTP, JWT:** R3-L1, R3-L2, R3-L3, R3-L4, R3-L6, R3-L7, R3-L11, R3-L12, R3-L44, R3-L45, R4-L1, R4-L2, R4-L3, R4-L4. |
| `dcaa592` (Q3) | **State, sessions, logout, health:** R3-L8, R3-L9, R3-L30, R3-L31, R3-L32, R3-L33, R3-L34 (Migration…19, provider FK `ON DELETE CASCADE`), R3-L35, R3-L36, R3-L37, R3-L39, R3-L40 (`sid` stored as `sha256:<hex>`), **R6-L1**. |
| `c936c2f`, merged in `e05879a` | **Frontend:** R3-F7 to R3-F17, **R6-L2**, Hygiene 1 (all `sw-*` form, card and button components migrated to Meteor `mt-*`, `$tc` replaced by `$t`, CI grep gate), Hygiene 2. The frontend side of R3-F9, R3-L17, R3-L18 and R3-L19. |
| `197f1da` (Q2) | **Passkeys and step-up (backend):** R3-F9 (backend), R3-L13 (20 keys per account, options budget), R3-L14 (same-origin check), R3-L15 (compare-and-set counter), R3-L16, R3-L19, R3-L41. |
| `e4161b9` (Q4) | **Identity and provisioning:** R3-L20 (IDN), R3-L21 (truncation), R3-L22, R3-L24, R3-L25, R3-L26, R3-L27, R3-L28, R4-L5 (`OidcCustomerLoginRoute` removed; logins go through `AccountService::loginById()`). |
| `87ae7e6` (Q6) | **DAL:** R3-L42, R3-L43 (`Choice`, `IntField` bounds, `claim_encoding` dropped by Migration…20, delete with bindings refused unless confirmed through the new delete endpoint). |
| `92f15bb` (Q8) | **Conventions:** R3-L5, R3-L10 (`Sw6OidcException`, an `HttpException`), R3-L38, R3-L46 (Twig runtime), R3-L47, R3-L50, R4-L6 (`web-token/jwt-library ^4.0`, transitive core dependencies dropped, `advisories.block: true`). |
| `d5f4b22` (Q9) | **Cleanup, static analysis, CI:** every unused-code row from revision 6. R3-L51 (actions pinned by SHA, `permissions: contents: read`, `assets` and `e2e` blocking, PHP 8.2 and 8.5 matrix). R4-L7 (`tests/E2E/specs/00-admin-smoke.spec.ts`). PHPStan level 8 for `src/`, Psalm `findUnusedCode`. |
| `2865d10` | **R7-H1** (new, see below). `bin/console lint:container` in CI. |
| docs commit | R3-L52 (`CLAUDE.md` refreshed). README, CHANGELOG. The last constructor defaults that hid misconfiguration (`SessionActivityController` session lifetimes). A missing R4-L4 unit test. |

### Closed by decision

| # | Decision |
|---|---|
| R3-L48 | **Won't fix.** `TestResultTranslator` keeps reading the Administration snippet JSON, so the popup and the provider page share one source of wording. The plugin is distributed through Composer only, and a Composer install always contains `Resources/app`. Documented in `CLAUDE.md`. |
| R3-L46 (write-guard half) | **Not needed.** The write guards on the global `PreWriteValidationEvent` return after one `instanceof` check per command, so making them lazy saves nothing measurable. The Twig half is fixed. |

### Numbers

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| Open | 0 | 0 | 0 | 2 partial (R3-L29, R3-L49), plus the test gate |
| Fixed in revision 7 | 0 | 1 (R7-H1) | 0 | 51 R3 + 7 R4 + 2 R6 backend Lows, 11 R3-F rows, 2 hygiene rows, 15 unused-code rows |

### Tooling (run on the working tree of this revision)

| Tool | Result |
|---|---|
| PHPUnit (unit) | **OK**, 869 tests, 2243 assertions (795 at revision 6) |
| PHPCS | clean |
| PHPStan level 8, `src/` (configured since `d5f4b22`) | no errors |
| PHPStan level 5, `tests/` (`phpstan.tests.neon.dist`) | no errors |
| Psalm (errorLevel 4, `findUnusedCode`, `psalm-baseline.xml`) | no errors |
| Rector (dry-run) | clean |
| `bin/console lint:container` | OK (it found R7-H1) |
| Migrations 19 and 20, plus the newly guarded early migrations | run and re-run on a MariaDB scratch database |
| Administration and Storefront bundles | rebuilt (`a9577b4`) |
| Integration / E2E | **not run.** They need a Docker shop plus Dex. CI runs them as blocking jobs now. |

---

## Revision 7: new finding (fixed)

| # | Severity | Where | What was wrong | Fix |
|---|---|---|---|---|
| R7-H1 | High | `Storefront/Controller/AccountPasskeyController.php` | The constructor type-hinted the concrete core `LogoutRoute`. The plugin decorates `LogoutRoute`, so the container passed the decorator and every request to *My account > Passkeys* failed with a `TypeError`. Neither the unit tests nor the static analysis catch a wiring error like this. | Type-hint `AbstractLogoutRoute`. CI runs `bin/console lint:container` in the `assets` job (`2865d10`). |

---

## Open

| # | Status | Where | What is left |
|---|---|---|---|
| Test gate | **open, blocks release** | `phpunit.integration.xml.dist`, `tests/E2E` | Run the integration and E2E suites against this branch, including `00-admin-smoke.spec.ts`. This round changed the customer login path (`AccountService::loginById()`), passkey ceremonies, the provider delete flow, session destruction and every admin page (the Meteor migration). Unit tests cover none of those end to end. |
| R3-L29 | partial | `CustomerProvisioningService`, `AdminProvisioningService` | The hand-written login copy is gone (R4-L5), and "skip unchanged values" is now shared. Find-by-email, reload-after-create and fallback names are still written twice. This is refactoring only: no behaviour is wrong. |
| R3-L49 | partial | `services.xml`, `AdminOidcGrant`, `PasswordLoginGuardClientRepository` | The bridge still depends on core OAuth internals (`FakeCryptKey`, core repositories). `CoreOAuthContractTest` now fails on any change to them, and request contexts are passed down wherever one exists. `Context::createDefaultContext()` remains for anonymous pre-auth routes, subscribers and CLI. Shopware has no public API for this, so it stays partial. |

## Edge cases from revision 6

Every row in the revision 6 table is fixed and has a unit test: R3-L1 (`ProviderResolverTest`), R3-L2 (`RelayStateValidatorTest`), R3-L21, R3-L24, R3-L43, R6-L1, R4-L3 (ES256/PS256 in `JwtVerifierTest`) and R4-L4 (`OidcCallbackProcessorIdpErrorTest`, added with the docs commit). R6-L2 is the exception: it is a browser-only path and is covered by the admin smoke spec, which hasn't been run yet.

---

## Future improvements (optional, after release)

- **9 Passkeys:**
  - Conditional mediation (`autocomplete="username webauthn"`).
  - A `PasskeyCredentialDeletedEvent`.
  - A clone-detection Flow Builder trigger.
  - One shared ceremony service for admin and storefront.
- **10 Bounded HTTP layer:**
  - Response-size caps on token, userinfo and JWKS responses.
  - Keep `error`/`error_description` from 4xx responses for diagnostics.
  - Separate HTTP clients for the IdP and for user content (`picture` URLs).
- **11 Protocol defaults:**
  - Enforce `S256` PKCE unless discovery lacks it.
  - Check `typ: logout+jwt` when the IdP sets it.
- **14 Configuration hygiene:**
  - A `Configuration` tree for the `SW6OIDC_*` env vars.
  - Autowiring (rev-2 L13, deferred).
- **15 Frontend architecture:**
  - A small pre-auth bundle for `sw-login` and the inactivity modal (also closes the rev-2 partials F-M2 and F-M14).
  - Show the `PublicError` correlation reference in toasts.
- **R3-L29 / R3-L49 rest:** see Open.

## Suggested next steps

1. **Run CI on `fix/code-review-rev2`.** It runs the integration suite, the E2E suite with the admin smoke spec, the assets job and `lint:container`, all blocking. Fix whatever fails first.
2. In a shop, do a manual pass of the paths this round changed:
   - Customer SSO login, including a customer the shop refuses ("account unavailable").
   - Admin SSO login, including an inactive admin.
   - Storefront and admin passkeys: register, log in, the 20-key limit.
   - Deleting a provider that has bindings.
   - Health endpoint with and without `SW6OIDC_HEALTH_TOKEN`.
   - Front-channel and back-channel logout against Authelia.
3. Then release. The open partials and the roadmap can follow.
