# Setting up Dex for the Shopware OIDC plugin

[Dex](https://dexidp.io/) is a federating OIDC provider: it puts LDAP, GitHub, Google, SAML and other connectors behind one OIDC interface. This guide connects it to the Shopware OIDC & Passkey SSO plugin. Replace `https://shop.example.com` with your shop's URL and `https://dex.example.com/dex` with your Dex issuer.

The plugin's own integration tests run against Dex. `tests/Integration/dex/config.yaml` is a minimal working configuration (plain HTTP on loopback, test-only).

## 1. Register the client in Dex

In Dex's configuration file:

```yaml
issuer: https://dex.example.com/dex

oauth2:
  responseTypes: ["code"]
  skipApprovalScreen: true      # otherwise users confirm the scopes on every login

staticClients:
  - id: shopware
    name: Shopware
    secret: <a long random secret>
    redirectURIs:
      - https://shop.example.com/sw6oidc/callback                       # Storefront login
      - https://shop.example.com/api/sw6oidc/admin/callback             # Administration login
      - https://shop.example.com/api/sw6oidc/provider/test-callback     # "Run live login test" button

connectors:
  # Your upstream identity source(s): ldap, github, oidc, saml, …
```

Dex authenticates confidential clients with HTTP Basic (`client_secret_basic`), which is what the plugin uses. PKCE (S256) is supported and always used by the plugin.

## 2. Create the provider in Shopware

*Settings → Plugins → OIDC Providers → Add provider*:

| Field | Value |
|---|---|
| Client ID / Client secret | `shopware` / the secret from step 1 |
| Well-known configuration URL | `https://dex.example.com/dex/.well-known/openid-configuration`, then **Load configuration** |
| Scope | `openid profile email groups` (`groups` only if your connector provides groups; `openid` is required — the plugin then expects an ID token) |
| PKCE flow | `S256` |
| Group attribute | `groups` |

Save, then use **Test connection** and **Run live login test**. Dex sends `sub`, `email`, `email_verified`, `name`, `preferred_username` and, with the `groups` scope and a connector that supports it, `groups`.

Dex's `sub` is an encoded combination of the connector and the upstream user id. It stays stable for a user as long as the connector id doesn't change. Shop accounts are bound to it, so renaming a connector id disconnects every account (unlink and connect again).

**Verified email**: the provider's **Require a verified email** setting is on by default, so the live test must show `email_verified: true`. Dex takes this value from the connector; check your connector's documentation if it is `false`. Turn the setting off only deliberately, if the upstream source fully controls every user's email address.

**Existing shop accounts** with the same email are not taken over automatically. Users connect them with **Connect SSO** in their account/profile, or you enable **Link existing accounts by verified email** on the provider.

**Step-up in the Administration**: confirming an admin's identity via SSO needs `auth_time` in the ID token. If Dex doesn't send it, admins confirm with a passkey or their password instead.

## 3. Groups and access control

- **Group/Role mapping**: map Dex group names to customer groups or ACL roles. For GitHub these look like `my-org:my-team`; for LDAP they come from the connector's `groupSearch`.
- **Access control**: for example `groups` *contains* `my-org:shop-admins`, or `email` *email domain is* `example.com`. (`email_verified` *equals* `true` is only needed when **Require a verified email** is off.)

## 4. Logout

Dex doesn't support RP-initiated logout (there is no `end_session_endpoint`), Back-Channel Logout or Front-Channel Logout. Logging out of the shop ends only the shop session. The Dex session (and the upstream login) stays, so the next SSO login may succeed without a password prompt. Leave the provider's **End-session endpoint** empty.

## 5. Troubleshooting

- **"Unregistered redirect_uri"**: the URI must match a `redirectURIs` entry exactly.
- **No `groups` claim**: request the `groups` scope, and check that the connector returns groups (for LDAP: `groupSearch`; for GitHub: `loadAllGroups` or `orgs`).
- **"email address not verified"**: the connector reported `email_verified: false`; see "Verified email" above.
- **Dex on a private network or plain HTTP (testing only)**: set `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1`, and never in production.
