import template from './sw-verify-user-modal.html.twig';
import { preparePublicKeyRequestOptions, serializeAssertionCredential } from '../../service/webauthn-codec';

const { Component } = Shopware;

const STEP_UP_MESSAGE_TYPE = 'sw6oidc-step-up';

/**
 * Core's "confirm your password" modal, extended with a fresh
 * re-authentication for admins who have no usable password (SSO) or prefer
 * their passkey: an OIDC round trip with prompt=login in a popup, or a
 * passkey assertion with user verification. Either way the server mints a
 * short-lived `user-verified` token (StepUpController), which is handed to
 * the caller exactly like core's password check does: installed as the
 * bearer token and emitted with `verified`.
 *
 * Replaces the former `ssoSettingsService.isSso()` decorator, which turned
 * every OIDC session into a password-less "native SSO" session (F-C1).
 */
Component.override('sw-verify-user-modal', {
    template,

    inject: ['sw6oidcApiService'],

    data() {
        return {
            sw6oidcStepUpMethods: { oidc: false, passkey: false },
            sw6oidcStepUpBusy: false,
            sw6oidcStepUpPopup: null,
            sw6oidcStepUpPopupTimer: null,
        };
    },

    created() {
        this.sw6oidcLoadStepUpMethods();
    },

    beforeUnmount() {
        window.removeEventListener('message', this.sw6oidcOnStepUpMessage);
        this.sw6oidcStopPopupWatch();
        this.sw6oidcStepUpPopup?.close();
        this.sw6oidcStepUpPopup = null;
    },

    methods: {
        async sw6oidcLoadStepUpMethods() {
            try {
                const methods = await this.sw6oidcApiService.get('sw6oidc/admin/step-up/methods');
                this.sw6oidcStepUpMethods = {
                    oidc: Boolean(methods?.oidc),
                    passkey: Boolean(methods?.passkey) && Boolean(window.PublicKeyCredential),
                };
            } catch {
                this.sw6oidcStepUpMethods = { oidc: false, passkey: false };
            }
        },

        sw6oidcStepUpWithSso() {
            // Opened synchronously in the click handler, or popup blockers intervene.
            const popup = window.open('about:blank', 'sw6oidcStepUp', 'width=520,height=720');

            if (!popup) {
                this.sw6oidcStepUpFailed();
                return;
            }

            this.sw6oidcStepUpBusy = true;
            this.sw6oidcStepUpPopup = popup;
            window.addEventListener('message', this.sw6oidcOnStepUpMessage);
            this.sw6oidcWatchPopup(popup);

            this.sw6oidcApiService.post('sw6oidc/admin/step-up/oidc/start')
                .then(({ authorizeUrl }) => {
                    if (this.sw6oidcStepUpPopup === popup && !popup.closed) {
                        popup.location.href = authorizeUrl;
                    }
                })
                .catch(() => {
                    popup.close();

                    if (this.sw6oidcStepUpPopup === popup) {
                        this.sw6oidcStepUpFailed();
                    }
                });
        },

        /**
         * Closing the IdP popup sends no message: without this, the buttons
         * stayed disabled (R3-F9). Closing it is a cancel, so nothing is shown.
         */
        sw6oidcWatchPopup(popup) {
            this.sw6oidcStopPopupWatch();
            this.sw6oidcStepUpPopupTimer = window.setInterval(() => {
                if (this.sw6oidcStepUpPopup !== popup) {
                    this.sw6oidcStopPopupWatch();
                    return;
                }

                if (popup.closed) {
                    this.sw6oidcStopPopupWatch();
                    window.removeEventListener('message', this.sw6oidcOnStepUpMessage);
                    this.sw6oidcStepUpPopup = null;
                    this.sw6oidcStepUpBusy = false;
                }
            }, 500);
        },

        sw6oidcStopPopupWatch() {
            if (this.sw6oidcStepUpPopupTimer !== null) {
                window.clearInterval(this.sw6oidcStepUpPopupTimer);
                this.sw6oidcStepUpPopupTimer = null;
            }
        },

        async sw6oidcOnStepUpMessage(event) {
            // Only the popup we opened, and only from the Administration's origin.
            if (event.origin !== window.location.origin
                || event.source !== this.sw6oidcStepUpPopup
                || event.data?.type !== STEP_UP_MESSAGE_TYPE) {
                return;
            }

            window.removeEventListener('message', this.sw6oidcOnStepUpMessage);
            this.sw6oidcStopPopupWatch();
            this.sw6oidcStepUpPopup = null;

            // The callback page also reports failures, as {error} (R3-F9).
            if (typeof event.data.nonce !== 'string') {
                this.sw6oidcStepUpFailed();
                return;
            }

            try {
                const tokenData = await this.sw6oidcApiService.post('sw6oidc/admin/step-up/token', { nonce: event.data.nonce });
                this.sw6oidcFinishStepUp(tokenData);
            } catch {
                this.sw6oidcStepUpFailed();
            }
        },

        async sw6oidcStepUpWithPasskey() {
            this.sw6oidcStepUpBusy = true;

            try {
                const { sessionId, options } = await this.sw6oidcApiService.post('sw6oidc/admin/step-up/passkey/options');
                const credential = await navigator.credentials.get({ publicKey: preparePublicKeyRequestOptions(options) });
                const tokenData = await this.sw6oidcApiService.post('sw6oidc/admin/step-up/passkey/verify', {
                    sessionId,
                    credential: JSON.stringify(serializeAssertionCredential(credential)),
                });

                this.sw6oidcFinishStepUp(tokenData);
            } catch {
                this.sw6oidcStepUpFailed();
            }
        },

        /**
         * Same hand-off as core's onSubmitConfirmPassword().
         */
        sw6oidcFinishStepUp(tokenData) {
            const verifiedToken = tokenData?.access_token;

            if (typeof verifiedToken !== 'string' || verifiedToken === '') {
                this.sw6oidcStepUpFailed();
                return;
            }

            const context = { ...Shopware.Context.api };
            context.authToken.access = verifiedToken;

            this.loginService.setBearerAuthentication({
                ...this.loginService.getBearerAuthentication(),
                access: verifiedToken,
            });

            this.sw6oidcStepUpBusy = false;
            this.$emit('verified', context);
            this.$emit('close');
        },

        sw6oidcStepUpFailed() {
            window.removeEventListener('message', this.sw6oidcOnStepUpMessage);
            this.sw6oidcStopPopupWatch();
            this.sw6oidcStepUpBusy = false;
            this.sw6oidcStepUpPopup = null;
            this.createNotificationError({ message: this.$t('sw6oidc.stepUp.error') });
        },
    },
});
