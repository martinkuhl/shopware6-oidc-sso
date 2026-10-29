import template from './sw6oidc-connect-sso.html.twig';
import Sw6oidcApiService from '../../service/sw6oidc-api.service';
import { fetchUserProviderBindings } from '../../service/user-provider-api';

const { Component, Mixin } = Shopware;

/**
 * "Connect single sign-on" for the logged-in admin's own, not yet connected
 * account: after a fresh confirmation (password, SSO or passkey), a round
 * trip to the chosen provider binds that IdP identity to exactly this
 * account (OidcAdminAuthController::startLink()). This is how existing
 * admins — superadmins included — get connected when providers don't link
 * accounts by email.
 *
 * Lazy factory: main.js is also loaded on the pre-auth login screen.
 */
Component.register('sw6oidc-connect-sso', () => Promise.resolve({
    template,

    inject: ['sw6oidcApiService'],

    mixins: [Mixin.getByName('notification')],

    props: {
        userId: {
            type: String,
            required: true,
        },
    },

    data() {
        return {
            providers: [],
            isBound: true,
            isLoading: true,
            isConnecting: false,
            pendingProviderId: null,
        };
    },

    created() {
        this.load();
        this.showLinkedNotice();
    },

    methods: {
        async load() {
            this.isLoading = true;

            try {
                const [bindings, options] = await Promise.all([
                    fetchUserProviderBindings('admin', [this.userId]),
                    this.sw6oidcApiService.get('sw6oidc/admin/login-options', { anonymous: true }),
                ]);

                this.isBound = Boolean(bindings[this.userId]);
                this.providers = Array.isArray(options?.ssoProviders) ? options.ssoProviders : [];
            } catch {
                this.providers = [];
            } finally {
                this.isLoading = false;
            }
        },

        onClickConnect(providerId) {
            this.pendingProviderId = providerId;
        },

        async onVerified() {
            const providerId = this.pendingProviderId;
            this.pendingProviderId = null;
            this.isConnecting = true;

            try {
                const { authorizeUrl } = await this.sw6oidcApiService.post('sw6oidc/admin/link/start', { providerId });
                window.location.href = authorizeUrl;
            } catch (error) {
                this.isConnecting = false;
                this.createNotificationError({
                    message: this.$t(Sw6oidcApiService.errorCode(error) === 'user_verification_required'
                        ? 'sw6oidc.userProvider.connectVerificationRequired'
                        : 'sw6oidc.userProvider.connectError'),
                });
            }
        },

        /**
         * The link callback returns to the profile with ?sw6oidc_linked=1.
         */
        showLinkedNotice() {
            if (this.$route?.query?.sw6oidc_linked === '1') {
                this.createNotificationSuccess({ message: this.$t('sw6oidc.userProvider.connectSuccess') });
            }
        },
    },
}));
