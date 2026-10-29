import template from './sw6oidc-rp-id-field.html.twig';

const { Component } = Shopware;
const { Criteria } = Shopware.Data;

const ADMIN_FIELD_NAME_SUFFIX = 'passkeyRpIdAdmin';

/**
 * Custom config.xml component (<component name="sw6oidc-rp-id-field">) for
 * the two passkey "Relying Party ID (domain)" overrides. The placeholder
 * shows the host that applies when the field is left empty (plan F-5):
 *
 * - scope "admin" (`passkeyRpIdAdmin`): the host of APP_URL, which is what
 *   PasskeyRelyingPartyResolver uses for the Administration;
 * - scope "storefront" (`passkeyRpId`, per sales channel): the host of the
 *   selected sales channel's first domain. With "All sales channels"
 *   selected (or a channel without a domain) there is no single host, so the
 *   field keeps the neutral placeholder from config.xml.
 *
 * sw-system-config renders it through sw-form-field-renderer, which binds
 * `value`, listens for `update:value` and passes every config.xml child tag
 * as an attribute (so `<scope>admin</scope>` arrives as the `scope` prop).
 * Without a `scope` tag the scope is derived from the field name.
 */
Component.register('sw6oidc-rp-id-field', {
    template,

    inject: {
        repositoryFactory: 'repositoryFactory',
        // Provided by sw-system-config (a computed ref of the selected channel, null = all).
        swSystemConfigCurrentSalesChannelId: {
            from: 'swSystemConfigCurrentSalesChannelId',
            default: null,
        },
    },

    emits: ['update:value'],

    props: {
        value: {
            type: String,
            required: false,
            default: null,
        },
        label: {
            type: String,
            required: false,
            default: null,
        },
        helpText: {
            type: String,
            required: false,
            default: null,
        },
        placeholder: {
            type: String,
            required: false,
            default: null,
        },
        /** 'admin' | 'storefront' */
        scope: {
            type: String,
            required: false,
            default: null,
            validator: (value) => value === null || ['admin', 'storefront'].includes(value),
        },
        /** The system config key, e.g. "Sw6Oidc.config.passkeyRpIdAdmin". */
        name: {
            type: String,
            required: false,
            default: null,
        },
        disabled: {
            type: Boolean,
            required: false,
            default: false,
        },
        error: {
            type: Object,
            required: false,
            default: null,
        },
    },

    data() {
        return {
            salesChannelHost: null,
            hostRequestId: 0,
        };
    },

    computed: {
        effectiveScope() {
            if (this.scope) {
                return this.scope;
            }

            return typeof this.name === 'string' && this.name.endsWith(ADMIN_FIELD_NAME_SUFFIX) ? 'admin' : 'storefront';
        },

        selectedSalesChannelId() {
            const injected = this.swSystemConfigCurrentSalesChannelId;

            return (injected && typeof injected === 'object' && 'value' in injected ? injected.value : injected) || null;
        },

        defaultHost() {
            return this.effectiveScope === 'admin' ? this.appUrlHost : this.salesChannelHost;
        },

        /** APP_URL from /api/_info/config; the Administration's own host as a fallback. */
        appUrlHost() {
            return hostOf(Shopware.Store.get('context')?.app?.config?.appUrl) || window.location.hostname || null;
        },

        effectivePlaceholder() {
            if (!this.defaultHost) {
                return this.placeholder;
            }

            const translationKey = 'sw6oidc.passkeySettings.rpIdPlaceholderWithHost';

            return this.$te(translationKey) ? this.$t(translationKey, { host: this.defaultHost }) : this.defaultHost;
        },
    },

    watch: {
        selectedSalesChannelId: {
            immediate: true,
            handler() {
                this.loadSalesChannelHost();
            },
        },
    },

    methods: {
        onInput(newValue) {
            this.$emit('update:value', newValue);
        },

        async loadSalesChannelHost() {
            const requestId = ++this.hostRequestId;
            const salesChannelId = this.selectedSalesChannelId;

            if (this.effectiveScope !== 'storefront' || !salesChannelId) {
                this.salesChannelHost = null;

                return;
            }

            const criteria = new Criteria(1, 1);
            criteria.addFilter(Criteria.equals('salesChannelId', salesChannelId));
            criteria.addSorting(Criteria.sort('createdAt', 'ASC'));

            let host = null;

            try {
                const domains = await this.repositoryFactory.create('sales_channel_domain').search(criteria, Shopware.Context.api);
                host = hostOf(domains.first()?.url);
            } catch {
                // No read access to sales channel domains: keep the neutral placeholder.
            }

            if (requestId === this.hostRequestId) {
                this.salesChannelHost = host;
            }
        },
    },
});

function hostOf(url) {
    if (typeof url !== 'string' || url === '') {
        return null;
    }

    try {
        return new URL(url).hostname || null;
    } catch {
        return null;
    }
}
