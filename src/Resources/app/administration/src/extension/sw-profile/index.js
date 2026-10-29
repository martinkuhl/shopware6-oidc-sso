import tabTemplate from './sw-profile-index.html.twig';
import './page/sw6oidc-profile-passkey';

const { Component, Module } = Shopware;

/**
 * Adds a "Passkeys" tab to the admin's own profile page ("Mein Profil") for
 * self-service register/delete of that admin's own credentials, kept
 * entirely separate from the Settings > Passkey-Einstellungen grid (that one
 * is the cross-admin lockout-recovery tool; this is "manage my own").
 *
 * sw-profile-index's tab bar is plain, hardcoded <sw-tabs-item> markup in
 * the exact v6.7.14.0 source this plugin targets (not the data-driven
 * mt-tabs used from 6.8 onward behind a feature flag) - appending a sibling
 * item right after the existing "General" tab's own named block is the
 * reliable way to inject into the middle of that markup via twig block
 * overriding, since block substitution happens on the raw template string
 * before Vue ever compiles it into a render tree.
 */
Component.override('sw-profile-index', {
    template: tabTemplate,
});

/**
 * routeMiddleware is Shopware's supported mechanism for adding a new child
 * route into an EXISTING module's route tree instead of creating a new
 * top-level menu entry - confirmed against module.factory.ts's
 * registerModule()/getModuleRoutes(): every module's already-built routes
 * (children already flattened to arrays, names/paths already absolute) are
 * passed through every registered routeMiddleware exactly once, so pushing
 * onto currentRoute.children here is enough; no routes manifest is needed
 * for this module at all.
 */
Module.register('sw6oidc-profile-passkey', {
    type: 'plugin',

    routeMiddleware(next, currentRoute) {
        if (currentRoute.name === 'sw.profile.index') {
            currentRoute.children.push({
                name: 'sw.profile.index.sw6oidcPasskey',
                path: `${currentRoute.path}/sw6oidc-passkey`,
                component: 'sw6oidc-profile-passkey',
                meta: {
                    parentPath: 'sw.profile.index',
                    privilege: 'user.update_profile',
                },
            });
        }

        next(currentRoute);
    },
});
