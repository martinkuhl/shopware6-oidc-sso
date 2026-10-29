import template from './sw-inactivity-login.html.twig';
import './sw-inactivity-login.scss';
import {
    preparePublicKeyRequestOptions,
    serializeAssertionCredential,
} from '../../service/webauthn-codec';
import Sw6oidcApiService from '../../service/sw6oidc-api.service';
import { rememberSsoReturnRoute } from '../../service/sso-return-route';
import { completeLogin, rememberRememberMe } from '../../service/login-completion';

const { Component } = Shopware;

/**
 * Adds "Login with <provider>" and "Login with Passkey" to core's inactivity
 * re-login modal. The modal resumes the session of `lastKnownUser`, so both
 * paths make sure the *same* admin comes back:
 *
 * - Passkey: the expected username goes to login-verify, which refuses an
 *   assertion by anybody else (F-H6).
 * - SSO: a full-page round trip. The page the admin was on and the expected
 *   username are stored for exactly this round trip (service/sso-return-route);
 *   the login screen only resumes the old session for the same admin (F-N1).
 *   Core's per-tab session entries (screenshot, previous route) are cleared
 *   before leaving, as core's own re-login does (F-N13).
 */
Component.override('sw-inactivity-login', {
    template,

    inject: ['loginService', 'sw6oidcApiService'],

    data() {
        return {
            sw6oidcPasskeyAvailable: false,
            /** @type {Array<{id: string, label: string|null}>} visible admin-scoped providers */
            sw6oidcSsoProviders: [],
            /** disable_non_oidc_admin_login is on: hide the password field (the server rejects it anyway). */
            sw6oidcPasswordLoginDisabled: false,
            sw6oidcPasskeyPending: false,
            sw6oidcPasskeyError: null,
        };
    },

    created() {
        this.sw6oidcLoadLoginOptions();
    },

    methods: {
        async sw6oidcLoadLoginOptions() {
            try {
                const { ssoProviders, passkeyAvailable, passwordLoginDisabled } = await this.sw6oidcApiService.get(
                    'sw6oidc/admin/login-options',
                    { anonymous: true },
                );

                this.sw6oidcSsoProviders = Array.isArray(ssoProviders) ? ssoProviders : [];
                this.sw6oidcPasskeyAvailable = Boolean(passkeyAvailable);
                // Only hide the password form when this screen offers another way in (F-N4).
                this.sw6oidcPasswordLoginDisabled = Boolean(passwordLoginDisabled)
                    && (this.sw6oidcSsoProviders.length > 0 || this.sw6oidcPasskeyAvailable);
            } catch {
                this.sw6oidcSsoProviders = [];
                this.sw6oidcPasskeyAvailable = false;
            }
        },

        sw6oidcSsoButtonLabel(provider) {
            return provider.label
                ? this.$t('sw-login.sw6oidc.login.ssoButtonWithProvider', { name: provider.label })
                : this.$t('sw-login.sw6oidc.login.ssoButton');
        },

        sw6oidcStartSsoLogin(providerId) {
            const previousRouteKey = `sw-admin-previous-route_${this.hash}`;
            let returnId = null;

            try {
                const previousRoute = JSON.parse(sessionStorage.getItem(previousRouteKey) || '{}');
                returnId = rememberSsoReturnRoute(previousRoute?.fullPath, this.lastKnownUser);
            } catch {
                // No previous route: land on the dashboard after re-login.
            }

            sessionStorage.removeItem(previousRouteKey);
            sessionStorage.removeItem(`inactivityBackground_${this.hash}`);
            rememberRememberMe(this.rememberMe);

            const query = `providerId=${encodeURIComponent(providerId)}${returnId ? `&sw6oidc_return=${returnId}` : ''}`;
            window.location.href = Sw6oidcApiService.absoluteUrl(`sw6oidc/admin/login?${query}`);
        },

        async sw6oidcStartPasskeyLogin() {
            if (!window.PublicKeyCredential) {
                this.sw6oidcPasskeyError = 'not_supported';
                return;
            }

            this.sw6oidcPasskeyError = null;
            this.sw6oidcPasskeyPending = true;

            try {
                const { sessionId, options } = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/login-options', {}, { anonymous: true });

                const assertion = await navigator.credentials.get({
                    publicKey: preparePublicKeyRequestOptions(options),
                });

                const tokenData = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/login-verify', {
                    sessionId,
                    credential: JSON.stringify(serializeAssertionCredential(assertion)),
                    // core keeps the *username* in lastKnownUser
                    expectedUsername: this.lastKnownUser,
                }, { anonymous: true });

                completeLogin(this.loginService, tokenData, this.rememberMe);

                // Core's own success path: route back, reload, wake other tabs.
                this.handleLoginSuccess();
            } catch (error) {
                this.sw6oidcPasskeyError = Sw6oidcApiService.errorCode(error) === 'different_user'
                    ? 'different_user'
                    : 'login_failed';
            } finally {
                this.sw6oidcPasskeyPending = false;
            }
        },
    },
});
