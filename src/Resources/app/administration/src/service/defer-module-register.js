const FIRST_DELAY_MS = 50;
const MAX_DELAY_MS = 1000;
const SLOW_WARNING_AFTER_MS = 30000;

/**
 * Runs `register` once `isReady()` returns true, polling with a growing
 * delay (50 ms up to 1 s) and **without a time limit** (R6-L2): on a slow
 * connection core's main chunk can take longer than any fixed budget, and
 * giving up would silently drop the registration. On the pre-auth login
 * screen (where this bundle is force-loaded, see
 * Resources/views/administration/index.html.twig) the services may never
 * appear; one poll per second there costs nothing. After 30 s a single
 * console warning says it is still waiting.
 */
export function whenReady(name, isReady, register) {
    const startedAt = Date.now();
    let warned = false;

    const attempt = (delay) => {
        let ready = false;

        try {
            ready = Boolean(isReady());
        } catch {
            ready = false;
        }

        if (ready) {
            register();

            return;
        }

        if (!warned && Date.now() - startedAt > SLOW_WARNING_AFTER_MS) {
            warned = true;
            // eslint-disable-next-line no-console
            console.warn(`sw6oidc: still waiting to register ${name}`);
        }

        setTimeout(() => attempt(Math.min(delay * 2, MAX_DELAY_MS)), delay);
    };

    attempt(FIRST_DELAY_MS);
}

/**
 * Module.register() with a `settingsItem` array touches the Pinia
 * "settingsItems" store synchronously and throws "Store with id
 * \"settingsItems\" not found" if that store doesn't exist yet. It doesn't
 * during this plugin's forced-early script execution on the login screen:
 * that store is only created once Shopware's own Application.start() runs.
 * On an ordinary post-login page load this registers on the first attempt.
 */
export function registerModuleWhenReady(name, config) {
    whenReady(
        `the "${name}" module`,
        // Shopware.Store (Pinia) replaces the deprecated Shopware.State (F-M14); get() throws while missing.
        () => Shopware.Store.get('settingsItems'),
        () => Shopware.Module.register(name, config),
    );
}
