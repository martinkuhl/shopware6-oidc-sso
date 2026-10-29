import template from './sw-users-permissions-user-listing.html.twig';
import { fetchUserProviderBindings } from '../../service/user-provider-api';

/**
 * Adds an "OIDC Provider" column to Settings > Users & permissions > Users.
 * Bindings for the current page are fetched in one batch request after each
 * getList(), since sw6oidc_user_provider has no DAL association to user.
 */
Shopware.Component.override('sw-users-permissions-user-listing', {
    template,

    data() {
        return {
            sw6oidcBindings: {},
            sw6oidcBindingsRequestId: 0,
        };
    },

    computed: {
        userColumns() {
            const columns = this.$super('userColumns');

            columns.push({
                property: 'sw6oidcProvider',
                label: this.$t('sw6oidc.userProvider.label'),
                sortable: false,
            });

            return columns;
        },
    },

    methods: {
        getList() {
            const result = this.$super('getList');

            Promise.resolve(result).then(() => this.sw6oidcLoadBindings());

            return result;
        },

        async sw6oidcLoadBindings() {
            // Paging/searching quickly must not let an older response win.
            const requestId = ++this.sw6oidcBindingsRequestId;
            const ids = Array.from(this.user ?? []).map((user) => user.id);

            try {
                const bindings = await fetchUserProviderBindings('admin', ids);

                if (requestId === this.sw6oidcBindingsRequestId) {
                    this.sw6oidcBindings = bindings;
                }
            } catch (exception) {
                // eslint-disable-next-line no-console
                console.error('sw6oidc: failed to load OIDC provider bindings', exception);

                if (requestId === this.sw6oidcBindingsRequestId) {
                    this.sw6oidcBindings = {};
                }
            }
        },
    },
});
