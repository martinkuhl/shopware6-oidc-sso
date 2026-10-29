# Setting up ZITADEL for the Shopware OIDC plugin

This guide connects [ZITADEL](https://zitadel.com/) (Cloud or self-hosted) to the Shopware OIDC & Passkey SSO plugin. Replace `https://shop.example.com` with your shop's URL and `https://example-abc123.zitadel.cloud` with your ZITADEL instance URL (the issuer).

## 1. Create the application in ZITADEL

1. In the ZITADEL console, open (or create) a **Project**, for example `Shopware`.
2. **New application** → type **Web**.
3. Authentication method: **Code**. This is a confidential client that authenticates with HTTP Basic, which is what the plugin uses. PKCE is always used on top.
4. **Redirect URIs**, only the flows you use:
   - `https://shop.example.com/sw6oidc/callback` (Storefront)
   - `https://shop.example.com/api/sw6oidc/admin/callback` (Administration)
   - `https://shop.example.com/api/sw6oidc/provider/test-callback` ("Run live login test" button)
5. **Post Logout URIs**: `https://shop.example.com/account/login` and `https://shop.example.com/admin/`. Alternatively, register only `https://shop.example.com/sw6oidc/postlogout` and enter it as the provider's **Post-logout redirect URI** in Shopware (see "Logout").
6. Create the application and copy the **Client ID** and **Client Secret**. ZITADEL shows the secret only once.
7. Under the application's **Token settings**, enable **User roles inside ID Token** and **User Info inside ID Token**. The second is optional, because the plugin also fetches userinfo.
8. In the **Project** settings, enable **Assert Roles on Authentication** so the roles claim is sent, and grant the roles to users under **Authorizations**.

## 2. Create the provider in Shopware

*Settings → Plugins → OIDC Providers → Add provider*:

| Field | Value |
|---|---|
| Client ID / Client secret | from step 1 |
| Well-known configuration URL | `https://example-abc123.zitadel.cloud/.well-known/openid-configuration`, then **Load configuration** (fills every endpoint, including end-session and revocation) |
| Scope | `openid profile email` (`openid` is required: the plugin then expects an ID token and fails the login without one) |
| PKCE flow | `S256` |
| Group attribute | `urn:zitadel:iam:org:project:roles` |
| Base64-encoded claims | empty, unless you map ZITADEL **metadata** claims, whose values are Base64-encoded: then `urn:zitadel:iam:user:metadata` (covers every metadata key under it) |

Save, then use **Test connection** and **Run live login test**, and set up the attribute mapping from the claims the live test shows.

**Base64-encoded claims** only decodes the claims listed there. Avoid `*` (all claims): it would also decode ordinary values that happen to be valid Base64 text.

**Verified email**: the provider's **Require a verified email** setting is on by default, so the live test must show `email_verified: true`. ZITADEL sends `true` once the user's email address is verified in ZITADEL. Turn the setting off only deliberately, if your ZITADEL instance fully controls every user's email address.

**Existing shop accounts** with the same email are not taken over automatically. Users connect them with **Connect SSO** in their account/profile, or you enable **Link existing accounts by verified email** on the provider.

## 3. Roles, groups and access control

ZITADEL sends project roles as an object keyed by role name, for example `{"shop-admin": {"<orgId>": "<org domain>"}}`. The plugin treats the role names as the user's groups:

- **Group/Role mapping**: map role keys such as `shop-admin` to ACL roles, or `b2b-customer` to a customer group.
- **Access control**: the rule `urn:zitadel:iam:org:project:roles` *contains* `shop-admin` lets only users with that role in. `email_verified` *equals* `true` requires a verified email address (only needed when **Require a verified email** is off).

## 4. Logout

- **RP-initiated logout**: works through the discovered end-session endpoint. The plugin sends `id_token_hint`, `post_logout_redirect_uri` and a signed `state`; the redirect URI must be in the app's **Post Logout URIs**.
- **Back-Channel Logout**: recent ZITADEL versions support OIDC Back-Channel Logout for applications. It may have to be enabled as a feature on your instance, so check your version's documentation. Where the application settings offer a Back-Channel Logout URI, enter `https://shop.example.com/sw6oidc/backchannel-logout`. ZITADEL then ends shop sessions when a user logs out at ZITADEL or a session is terminated there. Customers lose exactly the affected session; Administration users lose all their Administration sessions.
  - The logout token must contain `jti` and an `iat` no older than 5 minutes (60 seconds clock leeway), so keep the clocks of ZITADEL and the shop in sync.
  - To end a single session rather than all of a user's sessions, ZITADEL must put `sid` into the ID token.

## 5. Troubleshooting

- **No roles in the claims**: check **Assert Roles on Authentication** (project), **User roles inside ID Token** (application) and that the user has an authorization for the project.
- **`invalid_client`**: the application's authentication method must be *Code* (Basic). *POST* sends credentials in the body, which the plugin doesn't do.
- **Logins fail after changing `APP_SECRET`**: the client secret is stored encrypted with a key derived from it, so enter the secret again.
- **"email address not verified"**: the user's email isn't verified in ZITADEL; see "Verified email" above.
