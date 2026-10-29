/**
 * The Administration's handle on its current SSO login session
 * (`sw6oidc_login_session` in the plugin's token response). Sent back at
 * logout so the server ends exactly this session's registry entry and uses
 * its id_token as the IdP logout hint — the access token's jti can't be used
 * for that, it changes on every silent refresh.
 */
const STORAGE_KEY = 'sw6oidc-login-session';

export function rememberLoginSession(loginSessionId) {
    try {
        if (typeof loginSessionId === 'string' && /^[a-f0-9]{32}$/.test(loginSessionId)) {
            localStorage.setItem(STORAGE_KEY, loginSessionId);
        } else {
            localStorage.removeItem(STORAGE_KEY);
        }
    } catch {
        // Storage unavailable (private mode): logout falls back server-side.
    }
}

export function consumeLoginSession() {
    try {
        const value = localStorage.getItem(STORAGE_KEY);
        localStorage.removeItem(STORAGE_KEY);

        return value;
    } catch {
        return null;
    }
}
