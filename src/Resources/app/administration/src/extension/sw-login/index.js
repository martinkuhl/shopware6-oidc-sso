/**
 * Extends the Administration login form (`sw-login-login`) with one
 * "Login with <provider>" button per SSO provider, a "Login with Passkey"
 * button, and the nonce exchange that completes the OIDC hand-off
 * (/admin#/login?sw6oidc_nonce=…).
 *
 * Texts come from the `sw-login.sw6oidc.*` snippets: before login, core only
 * serves the `sw-login` and `global` snippet namespaces.
 */
import template from './sw-login.html.twig';
import './sw-login.scss';
import {
    preparePublicKeyRequestOptions,
    serializeAssertionCredential,
} from '../../service/webauthn-codec';
import Sw6oidcApiService from '../../service/sw6oidc-api.service';
import { clearSsoReturnRoute, consumeSsoReturnRoute } from '../../service/sso-return-route';
import { completeLogin, consumeRememberMe, rememberRememberMe } from '../../service/login-completion';

const { Component } = Shopware;

const ERROR_MESSAGES = {
    access_denied: 'errorAccessDenied',
    admin_role_missing: 'errorRoleMissing',
    admin_auto_create_disabled: 'errorAutoCreateDisabled',
    link_required: 'errorLinkRequired',
    email_not_verified: 'errorEmailNotVerified',
    provider_mismatch: 'errorProviderMismatch',
};

Component.override('sw-login-login', {
    template,

    inject: ['loginService', 'sw6oidcApiService'],

    data() {
        return {
            sw6oidcExchangeError: null,
            /** Admin-configured access-control message, redeemed from a one-time error ticket. */
            sw6oidcErrorDetail: null,
            sw6oidcPasskeyError: null,
            sw6oidcPasskeyPending: false,
            /** @type {Array<{id: string, label: string|null}>} one entry per visible admin-scoped provider */
            sw6oidcSsoProviders: [],
            sw6oidcPasskeyAvailable: false,
            /** disable_non_oidc_admin_login is on: hide the password fields and button (the server refuses password logins anyway). */
            sw6oidcPasswordLoginDisabled: false,
        };
    },

    created() {
        this.sw6oidcHandleCallback();
        this.sw6oidcLoadLoginOptions();
    },

    computed: {
        /**
         * Known denial reasons (OidcAdminAuthController::callback()) get their
         * own, pre-auth-safe message; anything else the generic one.
         */
        sw6oidcErrorMessage() {
            if (this.sw6oidcErrorDetail) {
                return this.sw6oidcErrorDetail;
            }

            return this.sw6oidcText(ERROR_MESSAGES[this.sw6oidcExchangeError] ?? 'error');
        },
    },

    methods: {
        sw6oidcText(key, values = {}) {
            // vue-i18n 10: named values are the second argument (a third one is read as options).
            return this.$t(`sw-login.sw6oidc.login.${key}`, values);
        },

        /**
         * core's bootLogin() skips the full app boot and flags
         * sw-login-should-reload; a login that doesn't go through core's own
         * handleLoginSuccess() must reload the same way, or the dashboard
         * stays blank (modules, menu and stores are never initialized).
         *
         * After an SSO re-login from the inactivity modal, the admin returns
         * to the page they were on and the other tabs waiting on the modal
         * are woken up — but only if the *same* admin logged in again (F-N1).
         */
        async sw6oidcFinishLogin(resume = null) {
            let target = { name: 'core' };

            if (resume && await this.sw6oidcIsSameAdmin(resume.expectedUsername)) {
                target = resume.fullPath;
                sessionStorage.removeItem('lastKnownUser');

                try {
                    const channel = new BroadcastChannel('session_channel');
                    channel.postMessage({ inactive: false });
                    channel.close();
                } catch {
                    // BroadcastChannel unsupported: other tabs just stay on their modal.
                }
            }

            await this.$router.push(target);

            if (sessionStorage.getItem('sw-login-should-reload')) {
                sessionStorage.removeItem('sw-login-should-reload');
                window.location.reload();
            }
        },

        async sw6oidcIsSameAdmin(expectedUsername) {
            if (typeof expectedUsername !== 'string' || expectedUsername === '') {
                return false;
            }

            try {
                const me = await this.sw6oidcApiService.get('_info/me');
                // `Accept: application/json` gives `{data: {username}}`; JSON:API nests it in `attributes` (R3-F4).
                const username = me?.data?.username ?? me?.data?.attributes?.username;

                return username === expectedUsername;
            } catch {
                return false;
            }
        },

        sw6oidcStartLogin(providerId) {
            rememberRememberMe(this.rememberMe);
            window.location.href = Sw6oidcApiService.absoluteUrl(`sw6oidc/admin/login?providerId=${encodeURIComponent(providerId)}`);
        },

        sw6oidcSsoButtonLabel(provider) {
            return provider.label
                ? this.sw6oidcText('ssoButtonWithProvider', { name: provider.label })
                : this.sw6oidcText('ssoButton');
        },

        /**
         * Anonymous: can only say whether SSO/passkeys are set up at all, never
         * anything about the person about to log in. Any failure leaves the
         * buttons hidden.
         */
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

        async sw6oidcStartPasskeyLogin() {
            if (!window.PublicKeyCredential) {
                this.sw6oidcPasskeyError = 'not_supported';
                return;
            }

            this.sw6oidcPasskeyError = null;
            this.sw6oidcPasskeyPending = true;

            try {
                // Usernameless: the browser offers the passkeys registered for this RP.
                const { sessionId, options } = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/login-options', {}, { anonymous: true });

                const assertion = await navigator.credentials.get({
                    publicKey: preparePublicKeyRequestOptions(options),
                });

                const tokenData = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/login-verify', {
                    sessionId,
                    credential: JSON.stringify(serializeAssertionCredential(assertion)),
                }, { anonymous: true });

                completeLogin(this.loginService, tokenData, this.rememberMe);
                await this.sw6oidcFinishLogin();
            } catch {
                this.sw6oidcPasskeyError = 'login_failed';
            } finally {
                this.sw6oidcPasskeyPending = false;
            }
        },

        async sw6oidcHandleCallback() {
            // Hash-mode router: the query lives in the fragment ("#/login?sw6oidc_nonce=…").
            const params = this.sw6oidcHashUrl().searchParams;
            const nonce = params.get('sw6oidc_nonce');
            const error = params.get('sw6oidc_error');
            const returnId = params.get('sw6oidc_return');

            if (error) {
                const ticket = params.get('sw6oidc_error_ticket');

                clearSsoReturnRoute();
                this.sw6oidcExchangeError = error;
                this.sw6oidcCleanUrl();

                if (ticket) {
                    await this.sw6oidcLoadErrorDetail(ticket);
                }

                return;
            }

            if (!nonce) {
                // A return route from an abandoned SSO attempt must not apply to this login (F-N9).
                clearSsoReturnRoute();
                return;
            }

            const resume = consumeSsoReturnRoute(returnId);
            const rememberMe = consumeRememberMe();

            try {
                // Grant type, client and scope are fixed on the server (R3-H1).
                const tokenData = await this.sw6oidcApiService.post('sw6oidc/admin/token', {
                    sw6oidc_nonce: nonce,
                }, { anonymous: true });

                completeLogin(this.loginService, tokenData, rememberMe);
                this.sw6oidcCleanUrl();
                await this.sw6oidcFinishLogin(resume);
            } catch {
                this.sw6oidcExchangeError = 'exchange_failed';
                this.sw6oidcCleanUrl();
            }
        },

        /**
         * Redeems the one-time error ticket an access-control denial carries
         * (the message itself never travels in the URL).
         */
        async sw6oidcLoadErrorDetail(ticket) {
            try {
                const { message } = await this.sw6oidcApiService.get(
                    `sw6oidc/admin/login-error/${encodeURIComponent(ticket)}`,
                    { anonymous: true },
                );

                this.sw6oidcErrorDetail = typeof message === 'string' && message !== '' ? message : null;
            } catch {
                // Keep the generic access-denied text.
            }
        },

        sw6oidcHashUrl() {
            return new URL(window.location.hash.slice(1) || '/', window.location.origin);
        },

        sw6oidcCleanUrl() {
            const hashUrl = this.sw6oidcHashUrl();
            ['sw6oidc_nonce', 'sw6oidc_error', 'sw6oidc_error_ticket', 'sw6oidc_return'].forEach((name) => {
                hashUrl.searchParams.delete(name);
            });

            const query = hashUrl.searchParams.toString();
            const newHash = `#${hashUrl.pathname}${query ? `?${query}` : ''}`;

            window.history.replaceState({}, document.title, window.location.pathname + newHash);
        },
    },
});
