import template from './sw6oidc-passkey-list.html.twig';

const { Component, Mixin } = Shopware;
const { Criteria } = Shopware.Data;

/**
 * Lockout-recovery grid: every registered passkey (admin + customer), with
 * delete for `sw6oidc_passkey_credential.deleter`. Registering a passkey is
 * self-service only — in "My profile > Passkeys", which asks for step-up
 * re-authentication first; this list doesn't duplicate that ceremony.
 *
 * Registered as a lazy factory, so the mixins are only resolved once
 * Shopware builds the component — never during the plugin's forced-early
 * script execution on the login screen, where they aren't registered yet.
 */
Component.register('sw6oidc-passkey-list', () => Promise.resolve({
    template,

    inject: ['repositoryFactory', 'acl'],

    mixins: [
        Mixin.getByName('notification'),
        Mixin.getByName('listing'),
    ],

    data() {
        return {
            credentials: null,
            isLoading: true,
            limit: 25,
            sortBy: 'createdAt',
            sortDirection: 'DESC',
            // `${userType}:${userId}` -> label; the credential's owner is a
            // polymorphic pair without a DAL association.
            ownerNames: {},
            requestId: 0,
        };
    },

    metaInfo() {
        return {
            title: this.$createTitle(),
        };
    },

    computed: {
        credentialRepository() {
            return this.repositoryFactory.create('sw6oidc_passkey_credential');
        },

        userRepository() {
            return this.repositoryFactory.create('user');
        },

        customerRepository() {
            return this.repositoryFactory.create('customer');
        },

        columns() {
            return [
                { property: 'userType', label: this.$t('sw6oidc.passkeySettings.list.columnUserType'), sortable: true },
                { property: 'owner', label: this.$t('sw6oidc.passkeySettings.list.columnOwner'), sortable: false },
                { property: 'nickname', label: this.$t('sw6oidc.passkeySettings.list.columnNickname'), sortable: true },
                { property: 'createdAt', label: this.$t('sw6oidc.passkeySettings.list.columnCreatedAt'), sortable: true },
            ];
        },
    },

    // No own created(): the listing mixin's created() already loads the list (R3-F11).

    methods: {
        async getList() {
            const requestId = ++this.requestId;
            this.isLoading = true;

            const criteria = new Criteria(this.page, this.limit);
            criteria.addSorting(Criteria.sort(this.sortBy, this.sortDirection));
            // Only what the grid shows; never the public key JSON (R3-L19).
            criteria.addIncludes({
                sw6oidc_passkey_credential: ['id', 'userType', 'userId', 'nickname', 'createdAt', 'disabledAt'],
            });

            try {
                const result = await this.credentialRepository.search(criteria, Shopware.Context.api);
                const ownerNames = await this.loadOwnerNames(result);

                // Only the newest request may update the list and the owner names (R3-F11).
                if (requestId === this.requestId) {
                    this.ownerNames = ownerNames;
                    this.total = result.total;
                    this.credentials = result;
                }
            } catch {
                if (requestId === this.requestId) {
                    this.createNotificationError({ message: this.$t('sw6oidc.passkeySettings.loadError') });
                }
            } finally {
                if (requestId === this.requestId) {
                    this.isLoading = false;
                }
            }
        },

        async loadOwnerNames(credentials) {
            const idsOf = (type) => [...new Set(credentials.filter((credential) => credential.userType === type).map((credential) => credential.userId))];
            const adminIds = idsOf('admin');
            const customerIds = idsOf('customer');

            const [admins, customers] = await Promise.all([
                adminIds.length
                    ? this.userRepository.search(new Criteria(1, adminIds.length).addFilter(Criteria.equalsAny('id', adminIds)), Shopware.Context.api)
                    : Promise.resolve([]),
                customerIds.length
                    ? this.customerRepository.search(new Criteria(1, customerIds.length).addFilter(Criteria.equalsAny('id', customerIds)), Shopware.Context.api)
                    : Promise.resolve([]),
            ]);

            const names = {};
            admins.forEach((admin) => {
                names[`admin:${admin.id}`] = admin.username;
            });
            customers.forEach((customer) => {
                names[`customer:${customer.id}`] = `${customer.firstName} ${customer.lastName}`.trim() || customer.email;
            });

            return names;
        },

        ownerName(item) {
            return this.ownerNames[`${item.userType}:${item.userId}`] || item.userId;
        },

        userTypeLabel(item) {
            return this.$t(`sw6oidc.passkeySettings.userType.${item.userType}`);
        },

        formatDate(value) {
            return value ? Shopware.Utils.format.date(value) : '—';
        },
    },
}));
