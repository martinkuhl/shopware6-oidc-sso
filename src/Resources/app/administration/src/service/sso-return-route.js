/**
 * Carries "where was the admin before re-login" across the full-page OIDC
 * round trip (inactivity modal → IdP → /admin#/login?sw6oidc_nonce=…).
 *
 * - The entry is tied to one round trip: a random id travels through the
 *   OIDC flow (relayState) and back in the callback URL, and the entry is
 *   only used when the id matches. An abandoned attempt can't leak into the
 *   next, unrelated login in the tab (F-N9).
 * - It remembers which admin was re-authenticating; the login screen
 *   compares that with who actually logged in, and only resumes the old
 *   session (return route, waking the other tabs) for the same admin (F-N1).
 * - Only plain in-app paths are accepted (F-N10).
 */
const STORAGE_KEY = 'sw6oidc-sso-return-route';
const MAX_AGE_MS = 10 * 60 * 1000;
const SAFE_PATH = /^\/(?![/\\])[A-Za-z0-9/_\-.?=&%]*$/;

function isSafePath(path) {
    return typeof path === 'string' && SAFE_PATH.test(path) && !/^\/login(?:[/?]|$)/.test(path);
}

function randomId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * @return {string|null} the round-trip id to pass to the SSO login, or null when nothing was stored
 */
export function rememberSsoReturnRoute(fullPath, expectedUsername) {
    if (!isSafePath(fullPath)) {
        return null;
    }

    const id = randomId();

    try {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
            id,
            fullPath,
            expectedUsername: typeof expectedUsername === 'string' ? expectedUsername : null,
            at: Date.now(),
        }));
    } catch {
        return null;
    }

    return id;
}

/**
 * Consumes the stored entry. Returns it only for the round trip it was made
 * for (matching id, not expired); anything else is discarded.
 *
 * @return {{fullPath: string, expectedUsername: string|null}|null}
 */
export function consumeSsoReturnRoute(returnId) {
    let entry = null;

    try {
        entry = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null');
        sessionStorage.removeItem(STORAGE_KEY);
    } catch {
        return null;
    }

    if (!entry
        || typeof returnId !== 'string'
        || entry.id !== returnId
        || !isSafePath(entry.fullPath)
        || Date.now() - Number(entry.at) > MAX_AGE_MS) {
        return null;
    }

    return { fullPath: entry.fullPath, expectedUsername: entry.expectedUsername ?? null };
}

/**
 * Drops a leftover entry (login screen booted without an SSO callback).
 */
export function clearSsoReturnRoute() {
    try {
        sessionStorage.removeItem(STORAGE_KEY);
    } catch {
        // Storage unavailable: nothing to clear.
    }
}
