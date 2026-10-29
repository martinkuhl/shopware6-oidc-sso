import template from './sw6oidc-sessions-list.html.twig';
import './sw6oidc-sessions-list.scss';

const { Component, Mixin } = Shopware;
const { Criteria } = Shopware.Data;

/**
 * Lists sw6oidc_session_activity rows, newest first, with an "only active"
 * filter and a "Force logout" action (SessionActivityController). Owner names
 * are resolved with extra lookups, like sw6oidc-passkey-list: the activity
 * row only has a polymorphic userType/userId pair, no real association.
 *
 * Registered as a lazy factory so Mixin.getByName('notification') is only
 * evaluated once Shopware builds the component (see sw6oidc-passkey-list).
 */
Component.register('sw6oidc-sessions-list', () => Promise.resolve({
    template,

    inject: ['repositoryFactory', 'acl', 'sw6oidcApiService'],

    mixins: [Mixin.getByName('notification')],

    data() {
        return {
            activities: null,
            isLoading: true,
            page: 1,
            limit: 25,
            onlyActive: false,
            ownerNames: {},
            forceLogoutPendingId: null,
            confirmItem: null,
            sessionLifetimeSeconds: {},
            requestId: 0,
        };
    },

    metaInfo() {
        return {
            title: this.$createTitle(),
        };
    },

    computed: {
        activityRepository() {
            return this.repositoryFactory.create('sw6oidc_session_activity');
        },

        userRepository() {
            return this.repositoryFactory.create('user');
        },

        customerRepository() {
            return this.repositoryFactory.create('customer');
        },

        canForceLogout() {
            return this.acl.can('sw6oidc_session_activity.force_logout');
        },

        columns() {
            return [
                // Always newest first; the listing can't re-sort (F-N11).
                { property: 'loggedInAt', label: this.$t('sw6oidc.sessions.list.columnLoggedInAt'), sortable: false },
                { property: 'userType', label: this.$t('sw6oidc.sessions.list.columnUserType'), sortable: false },
                { property: 'owner', label: this.$t('sw6oidc.sessions.list.columnOwner'), sortable: false },
                { property: 'loginMethod', label: this.$t('sw6oidc.sessions.list.columnLoginMethod'), sortable: false },
                { property: 'provider', label: this.$t('sw6oidc.sessions.list.columnProvider'), sortable: false },
                { property: 'ipAddress', label: this.$t('sw6oidc.sessions.list.columnIpAddress'), sortable: false },
                { property: 'loggedOutAt', label: this.$t('sw6oidc.sessions.list.columnLoggedOutAt'), sortable: false },
                { property: 'logoutReason', label: this.$t('sw6oidc.sessions.list.columnLogoutReason'), sortable: false },
            ];
        },

        confirmText() {
            if (!this.confirmItem) {
                return '';
            }

            // Only a registered customer OIDC session is ended exactly; passkey
            // logins and admins lose all their sessions (F-N12).
            const endsAll = this.confirmItem.userType === 'admin' || this.confirmItem.loginMethod === 'passkey';

            return this.$t(endsAll ? 'sw6oidc.sessions.forceLogoutConfirmAll' : 'sw6oidc.sessions.forceLogoutConfirm');
        },
    },

    watch: {
        onlyActive() {
            this.page = 1;
            this.getList();
        },
    },

    async created() {
        // The lifetimes decide which rows "only active" shows, so they come first.
        await this.loadSettings();
        this.getList();
    },

    methods: {
        async loadSettings() {
            try {
                const { sessionLifetimeSeconds } = await this.sw6oidcApiService.get('_action/sw6oidc/session-activity/settings');
                this.sessionLifetimeSeconds = sessionLifetimeSeconds ?? {};
            } catch {
                this.sessionLifetimeSeconds = {};
            }
        },

        async getList() {
            // Only the newest request may update the list (F-N11).
            const requestId = ++this.requestId;
            this.isLoading = true;

            const criteria = new Criteria(this.page, this.limit);
            criteria.addAssociation('provider');
            criteria.addSorting(Criteria.sort('loggedInAt', 'DESC'));

            if (this.onlyActive) {
                criteria.addFilter(Criteria.equals('loggedOutAt', null));
                this.addNotExpiredFilter(criteria);
            }

            try {
                const result = await this.activityRepository.search(criteria, Shopware.Context.api);
                await this.loadOwnerNames(result);

                if (requestId === this.requestId) {
                    this.activities = result;
                }
            } catch (exception) {
                if (requestId === this.requestId) {
                    this.createNotificationError({ message: this.$t('sw6oidc.sessions.loadError') });
                }
            } finally {
                if (requestId === this.requestId) {
                    this.isLoading = false;
                }
            }
        },

        /**
         * 'active' | 'expired' (no logout recorded, but older than the
         * session lifetime) | 'ended' — a missing logout is not proof the
         * session still exists (F-N3).
         */
        sessionState(item) {
            if (item.loggedOutAt) {
                return 'ended';
            }

            const lifetime = this.sessionLifetimeSeconds[item.userType];

            if (!lifetime || !item.loggedInAt) {
                return 'active';
            }

            return Date.now() - new Date(item.loggedInAt).getTime() > lifetime * 1000 ? 'expired' : 'active';
        },

        /**
         * "Only active" leaves out the rows sessionState() labels expired
         * (R3-F13): per account type, logged in within its session lifetime.
         * A type without a known lifetime is not filtered.
         */
        addNotExpiredFilter(criteria) {
            const now = Date.now();
            const perType = ['admin', 'customer'].map((userType) => {
                const lifetime = this.sessionLifetimeSeconds[userType];

                if (!lifetime) {
                    return Criteria.equals('userType', userType);
                }

                // DAL date format (UTC, "Y-m-d H:i:s").
                const cutoff = new Date(now - lifetime * 1000).toISOString().slice(0, 19).replace('T', ' ');

                return Criteria.multi('AND', [
                    Criteria.equals('userType', userType),
                    Criteria.range('loggedInAt', { gte: cutoff }),
                ]);
            });

            criteria.addFilter(Criteria.multi('OR', perType));
        },

        onPageChange({ page, limit }) {
            this.page = page;
            this.limit = limit;
            this.getList();
        },

        async loadOwnerNames(activities) {
            const idsOf = (type) => [...new Set(activities.filter((activity) => activity.userType === type).map((activity) => activity.userId))];
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

            this.ownerNames = names;
        },

        ownerName(item) {
            return this.ownerNames[`${item.userType}:${item.userId}`] || item.userId;
        },

        providerName(item) {
            return item.provider ? (item.provider.displayName || item.provider.appName) : '—';
        },

        formatDate(value) {
            return value ? Shopware.Utils.format.date(value) : '—';
        },

        translated(prefix, value) {
            return value ? this.$t(`sw6oidc.sessions.${prefix}.${value}`) : '—';
        },

        onForceLogout(item) {
            this.confirmItem = item;
        },

        onCancelForceLogout() {
            this.confirmItem = null;
        },

        async onConfirmForceLogout() {
            const item = this.confirmItem;
            this.confirmItem = null;

            if (!item) {
                return;
            }

            this.forceLogoutPendingId = item.id;

            try {
                const { endedAllSessions } = await this.sw6oidcApiService.post(
                    `_action/sw6oidc/session-activity/${encodeURIComponent(item.id)}/force-logout`,
                );

                this.createNotificationSuccess({
                    message: this.$t(endedAllSessions ? 'sw6oidc.sessions.forceLogoutSuccessAll' : 'sw6oidc.sessions.forceLogoutSuccess'),
                });
                await this.getList();
            } catch (exception) {
                // eslint-disable-next-line no-console
                console.error('sw6oidc: force logout failed', exception);
                this.createNotificationError({ message: this.$t('sw6oidc.sessions.forceLogoutError') });
            } finally {
                this.forceLogoutPendingId = null;
            }
        },
    },
}));
