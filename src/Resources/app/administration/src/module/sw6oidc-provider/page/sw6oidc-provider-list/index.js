import template from './sw6oidc-provider-list.html.twig';

const { Component, Mixin } = Shopware;
const { Criteria } = Shopware.Data;

/**
 * Provider list with working paging/sorting (listing mixin, F-M4) and error
 * handling (F-M5). Registered as a lazy factory so the mixins resolve only
 * when the component is built (never on the pre-auth login screen).
 */
Component.register('sw6oidc-provider-list', () => Promise.resolve({
    template,

    inject: ['repositoryFactory', 'acl', 'sw6oidcApiService'],

    mixins: [
        Mixin.getByName('notification'),
        Mixin.getByName('listing'),
    ],

    data() {
        return {
            providers: null,
            isLoading: true,
            limit: 25,
            sortBy: 'sortOrder',
            sortDirection: 'ASC',
            requestId: 0,
            isDeleting: false,
        };
    },

    metaInfo() {
        return {
            title: this.$createTitle(),
        };
    },

    computed: {
        providerRepository() {
            return this.repositoryFactory.create('sw6oidc_provider');
        },

        columns() {
            return [
                { property: 'displayName', label: this.$t('sw6oidc.provider.list.columnDisplayName'), routerLink: 'sw6oidc.provider.detail', primary: true },
                { property: 'appName', label: this.$t('sw6oidc.provider.list.columnAppName') },
                { property: 'loginType', label: this.$t('sw6oidc.provider.list.columnLoginType') },
                { property: 'isActive', label: this.$t('sw6oidc.provider.list.columnActive') },
                { property: 'lastTestStatus', label: this.$t('sw6oidc.provider.list.columnLastTestStatus') },
            ];
        },
    },

    // No own created(): the listing mixin's created() already loads the list (R3-F11).

    methods: {
        /**
         * Deleting a provider disconnects its accounts from SSO (their
         * bindings go with it): the server refuses a plain delete while
         * bindings exist, so the confirmed delete uses the plugin's endpoint (R3-L43).
         */
        async onDeleteProvider(id) {
            this.isDeleting = true;

            try {
                await this.sw6oidcApiService.post(`_action/sw6oidc/provider/${id}/delete`);
                await this.getList();
            } catch {
                this.createNotificationError({ message: this.$t('sw6oidc.provider.list.deleteError') });
            } finally {
                this.isDeleting = false;
            }
        },

        async getList() {
            const requestId = ++this.requestId;
            this.isLoading = true;

            const criteria = new Criteria(this.page, this.limit);
            criteria.addSorting(Criteria.sort(this.sortBy, this.sortDirection));

            try {
                const result = await this.providerRepository.search(criteria, Shopware.Context.api);

                if (requestId === this.requestId) {
                    this.total = result.total;
                    this.providers = result;
                }
            } catch {
                if (requestId === this.requestId) {
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.list.loadError') });
                }
            } finally {
                if (requestId === this.requestId) {
                    this.isLoading = false;
                }
            }
        },
    },
}));
