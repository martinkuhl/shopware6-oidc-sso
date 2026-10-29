import { rememberLoginSession } from './login-session';

/**
 * The one way the plugin's login paths (OIDC nonce exchange, passkey — on
 * the login screen and in the inactivity modal) install a token response,
 * doing what core's loginByUsername() does around it: honour "remember me",
 * reset the inactivity clock (a stale lastActivity would log the fresh
 * session out on the first refresh) and set the bearer authentication (F-M1).
 */
const REMEMBER_ME_KEY = 'sw6oidc-remember-me';

export function completeLogin(loginService, tokenData, rememberMe = false) {
    loginService.setRememberMe(Boolean(rememberMe));
    Shopware.Service('userActivityService').updateLastUserActivity();

    loginService.setBearerAuthentication({
        access: tokenData.access_token,
        refresh: tokenData.refresh_token,
        expiry: tokenData.expires_in,
    });

    rememberLoginSession(tokenData.sw6oidc_login_session);
}

/**
 * "Remember me" has to survive the full-page OIDC round trip.
 */
export function rememberRememberMe(value) {
    try {
        sessionStorage.setItem(REMEMBER_ME_KEY, value ? '1' : '0');
    } catch {
        // Storage unavailable: the session just isn't remembered.
    }
}

export function consumeRememberMe() {
    try {
        const value = sessionStorage.getItem(REMEMBER_ME_KEY) === '1';
        sessionStorage.removeItem(REMEMBER_ME_KEY);

        return value;
    } catch {
        return false;
    }
}
