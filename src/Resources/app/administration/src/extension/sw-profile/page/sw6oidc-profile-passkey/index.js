import template from './sw6oidc-profile-passkey.html.twig';
import {
    preparePublicKeyCreationOptions,
    serializeAttestationCredential,
} from '../../../../service/webauthn-codec';

const { Component, Mixin } = Shopware;

/**
 * Self-service passkey management on the admin's own profile page
 * ("My profile" > Passkeys tab) — register/delete only the currently
 * authenticated admin's own credentials (PasskeyAdminController). Adding a
 * passkey first asks for a fresh confirmation (password, SSO or an existing
 * passkey, see the sw-verify-user-modal override): a hijacked session alone
 * must not be able to add a permanent way in.
 *
 * Registered as a lazy factory: main.js is force-loaded on the pre-auth
 * login screen too, where the "notification" mixin isn't registered yet.
 */
Component.register('sw6oidc-profile-passkey', () => Promise.resolve({
    template,

    inject: ['loginService', 'sw6oidcApiService'],

    mixins: [Mixin.getByName('notification')],

    data() {
        return {
            credentials: [],
            isLoading: true,
            isRegistering: false,
            deletingId: null,
            nickname: '',
            showVerifyModal: false,
            credentialToDelete: null,
        };
    },

    computed: {
        columns() {
            return [
                { property: 'nickname', label: this.$t('sw6oidc.passkeySettings.list.columnNickname') },
                { property: 'createdAt', label: this.$t('sw6oidc.passkeySettings.list.columnCreatedAt') },
            ];
        },

        dateFilter() {
            return Shopware.Filter.getByName('date');
        },
    },

    created() {
        this.getList();
    },

    methods: {
        async getList() {
            this.isLoading = true;

            try {
                const { credentials } = await this.sw6oidcApiService.get('sw6oidc/admin/passkey/my-credentials');
                this.credentials = Array.isArray(credentials) ? credentials : [];
            } catch {
                this.createNotificationError({ message: this.$t('sw6oidc.passkeySettings.loadError') });
            } finally {
                this.isLoading = false;
            }
        },

        onClickRegister() {
            if (!window.PublicKeyCredential) {
                this.createNotificationError({ message: this.$t('sw6oidc.passkeySettings.registerNoSupport') });
                return;
            }

            this.showVerifyModal = true;
        },

        /**
         * The confirmation installed a `user-verified` token as the bearer;
         * the registration request below carries it.
         */
        onVerified() {
            this.showVerifyModal = false;
            this.registerPasskey();
        },

        async registerPasskey() {
            this.isRegistering = true;

            try {
                const { sessionId, options } = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/registration-options');

                const credential = await navigator.credentials.create({
                    publicKey: preparePublicKeyCreationOptions(options),
                });

                await this.sw6oidcApiService.post('sw6oidc/admin/passkey/registration-verify', {
                    sessionId,
                    credential: JSON.stringify(serializeAttestationCredential(credential)),
                    nickname: this.nickname.trim() || null,
                });

                this.nickname = '';
                this.createNotificationSuccess({ message: this.$t('sw6oidc.passkeySettings.registerSuccess') });
                await this.getList();
            } catch {
                this.createNotificationError({ message: this.$t('sw6oidc.passkeySettings.registerError') });
            } finally {
                this.isRegistering = false;
            }
        },

        async deleteCredential(item) {
            this.credentialToDelete = null;
            this.deletingId = item.id;

            try {
                const result = await this.sw6oidcApiService.post('sw6oidc/admin/passkey/delete', { id: item.id });

                // The deleted passkey authenticated this very session: end it.
                if (result?.forceLogout) {
                    this.createNotificationSuccess({ message: this.$t('sw6oidc.passkeySettings.deleteSuccessLoggedOut') });
                    this.loginService.logout();
                    return;
                }

                this.createNotificationSuccess({ message: this.$t('sw6oidc.passkeySettings.deleteSuccess') });
                await this.getList();
            } catch {
                this.createNotificationError({ message: this.$t('sw6oidc.passkeySettings.deleteError') });
            } finally {
                this.deletingId = null;
            }
        },
    },
}));
