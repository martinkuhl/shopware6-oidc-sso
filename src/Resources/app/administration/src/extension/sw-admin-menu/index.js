import { consumeLoginSession } from '../../service/login-session';
import Sw6oidcApiService from '../../service/sw6oidc-api.service';

const { Component } = Shopware;

/**
 * RP-Initiated Logout for Administration users: core's user-menu logout
 * (loginService.logoutSso()) is purely client-side, so an admin who logged in
 * via OIDC would keep their IdP session and be signed straight back in by the
 * next "Login with SSO". Before the normal logout, ask the plugin for the
 * IdP's logout URL; if there is one, do the same local cleanup core does and
 * navigate there instead of to #/login. Any failure falls back to core's
 * stock logout. Inactivity logouts don't pass through here and stay local.
 *
 * The logout URL is requested through Shopware's HTTP client, which refreshes
 * an expired access token first — a raw fetch() got a 401 after ten minutes
 * and silently skipped the IdP logout (F-N2).
 */
Component.override('sw-admin-menu', {
    inject: ['sw6oidcApiService'],

    methods: {
        async onLogoutUser() {
            const logoutUrl = await this.sw6oidcFetchLogoutUrl();
            const token = this.loginService.getToken();

            if (!logoutUrl) {
                await this.$super('onLogoutUser');
                return;
            }

            try {
                // Same best-effort server-side revocation core's logoutSso() does,
                // via native fetch to bypass the refresh-token interceptor.
                await fetch(Sw6oidcApiService.absoluteUrl('_action/user/logout'), {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${token}` },
                });
            } catch {
                // Best-effort: continue even if server-side revocation fails
            }

            this.loginService.logout(false, false);
            // logout() pushes #/login and flags it to reload itself on mount;
            // that reload would cancel the navigation to the IdP below.
            sessionStorage.removeItem('refresh-after-logout');

            this.adminMenuStore.clearExpandedMenuEntries();
            Shopware.Store.get('session').removeCurrentUser();
            Shopware.Store.get('notification').clearGrowlNotificationsForCurrentUser();
            Shopware.Store.get('notification').clearNotificationsForCurrentUser();

            window.location.href = logoutUrl;
        },

        async sw6oidcFetchLogoutUrl() {
            if (!this.loginService.getToken()) {
                return null;
            }

            try {
                const loginSession = consumeLoginSession();
                const { logoutUrl } = await this.sw6oidcApiService.post(
                    'sw6oidc/admin/logout',
                    loginSession ? { sw6oidc_login_session: loginSession } : {},
                );

                return this.sw6oidcSafeUrl(logoutUrl);
            } catch (exception) {
                // eslint-disable-next-line no-console
                console.error('sw6oidc: failed to resolve admin IdP logout URL', exception);
                return null;
            }
        },

        /**
         * Only http(s) URLs are navigated to (F-N14).
         */
        sw6oidcSafeUrl(value) {
            if (typeof value !== 'string' || value === '') {
                return null;
            }

            try {
                const url = new URL(value);

                return ['https:', 'http:'].includes(url.protocol) ? url.toString() : null;
            } catch {
                return null;
            }
        },
    },
});
