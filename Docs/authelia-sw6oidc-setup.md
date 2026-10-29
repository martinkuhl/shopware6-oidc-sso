# Setting up Authelia for the Shopware OIDC plugin

This guide connects [Authelia](https://www.authelia.com/) (4.38 or newer) to the Shopware OIDC & Passkey SSO plugin, for Storefront customers, Administration users, or both. Replace `https://shop.example.com` with your shop's URL and `https://auth.example.com` with your Authelia URL.

## 1. Register the client in Authelia

Authelia stores a *hash* of the client secret; Shopware needs the plain secret. Generate both:

```bash
authelia crypto hash generate pbkdf2 --variant sha512 --random --random.length 64 --random.charset alphanumeric
```

The output shows `Random Password` (enter this in Shopware) and `Digest` (put this into Authelia's configuration).

Add the client to `configuration.yml`:

```yaml
identity_providers:
  oidc:
    # hmac_secret and jwks (an RS256 signing key) must already be configured.
    clients:
      - client_id: 'shopware'
        client_name: 'Shopware'
        client_secret: '$pbkdf2-sha512$310000$…'   # the Digest from above
        public: false
        authorization_policy: 'two_factor'
        consent_mode: 'implicit'                   # or 'pre-configured'; 'explicit' asks users every time
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'https://shop.example.com/sw6oidc/callback'                     # Storefront login
          - 'https://shop.example.com/api/sw6oidc/admin/callback'           # Administration login
          - 'https://shop.example.com/api/sw6oidc/provider/test-callback'   # "Run live login test" button
        scopes: ['openid', 'profile', 'email', 'groups']
        grant_types: ['authorization_code']
        response_types: ['code']
        token_endpoint_auth_method: 'client_secret_basic'
```

Only list the redirect URIs of the flows you use. Authelia compares them character by character, including the scheme and trailing slashes.

Restart Authelia and check the logs for configuration errors.

## 2. Create the provider in Shopware

*Settings → Plugins → OIDC Providers → Add provider*:

| Field | Value |
|---|---|
| Client ID | `shopware` |
| Client secret | the `Random Password` from step 1 |
| Well-known configuration URL | `https://auth.example.com/.well-known/openid-configuration`, then **Load configuration** |
| End-session endpoint | `https://auth.example.com/logout` — enter it by hand (see below) |
| Scope | `openid profile email groups` (`openid` is required: the plugin then expects an ID token and fails the login without one) |
| PKCE flow | `S256` |
| Group attribute | `groups` |
| Login type | customer, admin or both |

Save, then use **Test connection** and **Run live login test**. The live test shows every claim Authelia sends. Use it to set up the attribute mapping (Authelia sends `email`, `email_verified`, `name`, `preferred_username`, `groups`).

Since Authelia 4.39, most claims come from the userinfo endpoint rather than the ID token. That's fine: the plugin always fetches userinfo and merges both (userinfo must describe the same `sub`; `sub`, `email` and `email_verified` are taken from the ID token when it contains them).

**Verified email**: the provider's **Require a verified email** setting is on by default, so the live test must show `email_verified: true`. Turn the setting off only deliberately, if your Authelia user database is the only source of email addresses and you trust it completely.

**Existing shop accounts** with the same email are not taken over automatically. Users connect them with **Connect SSO** in their account/profile, or you enable **Link existing accounts by verified email** on the provider.

## 3. Groups, roles and access control

- **Group/Role mapping**: map Authelia group names (as listed under `groups` in your user database or LDAP) to customer groups or ACL roles.
- **Access control**: for example, to allow only members of `shop-staff` into the Administration, use a provider with login type `admin` and the rule `groups` *contains* `shop-staff`.

## 4. Logout

Authelia has no standard `end_session_endpoint`, so auto-discovery leaves that field empty. Set it to the portal logout page `https://auth.example.com/logout`. The plugin recognizes this shape and sends `?rd=<url>` instead of the standard OIDC logout parameters. You don't need to register a post-logout URI with Authelia.

To send users somewhere other than the login page, set the provider's **Post-logout redirect URI**. That URL must be allowed by Authelia's redirection rules (the same domain as your protected sites).

At the time of writing, Authelia supports neither **Back-Channel** nor **Front-Channel Logout**. Logging out at Authelia directly does not end shop sessions.

## 5. Troubleshooting

- **`invalid_client` at the token endpoint**: the client secret in Shopware must be the plain value, not the digest, and `token_endpoint_auth_method` must be `client_secret_basic` (or be left out).
- **"The 'redirect_uris' registered … did not match"**: add the exact URI from the error to `redirect_uris`.
- **Login loops back to the login page**: check the plugin log `var/log/sw6oidc-<env>.log` (switch on **Enable debug logging** in the plugin settings for details).
- **"email address not verified"**: Authelia didn't send `email_verified: true`; see "Verified email" above.
- **Private addresses**: the plugin only talks to IdPs on public HTTPS addresses. For a test setup on a local network, set `SW6OIDC_ALLOW_INSECURE_IDP_URLS=1`, and never in production.
