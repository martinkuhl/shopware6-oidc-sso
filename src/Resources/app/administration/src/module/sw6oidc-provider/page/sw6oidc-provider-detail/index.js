import template from './sw6oidc-provider-detail.html.twig';
import './sw6oidc-provider-detail.scss';

const { Component, Mixin } = Shopware;
const { Criteria } = Shopware.Data;

/**
 * Protocol/token-metadata claims — never useful as an attribute-mapping
 * target (there's no Shopware field they'd sensibly map to). `sub`/
 * `updated_at` deliberately excluded here too even though they're valid
 * OIDC standard claims: `sub` is an opaque per-IdP identifier with nothing
 * to map it to, and `updated_at` is a timestamp, not an identity field.
 *
 * Matched by exact key AND by dot-flattened prefix (`amr.0`, `aud.1`, ...):
 * ClaimsNormalizer::flatten() turns an array-valued claim like
 * `amr: ["pwd", "otp"]` into `amr.0`/`amr.1` — see isTechnicalClaim() below.
 */
const TECHNICAL_CLAIM_EXCLUSIONS = new Set([
    'amr',
    'at_hash',
    'aud',
    'auth_time',
    'azp',
    'exp',
    'iat',
    'iss',
    'jti',
    'nonce',
    'sub',
    'rat',
    'updated_at',
]);

/**
 * Discovery may only fill these fields — never mass-assign the response (F-M7).
 */
const DISCOVERED_ENDPOINT_FIELDS = [
    'authorizeEndpoint',
    'accessTokenEndpoint',
    'userInfoEndpoint',
    'jwksEndpoint',
    'endSessionEndpoint',
    'revocationEndpoint',
    'issuer',
];

/** Save errors shown with a translated message instead of the server's English detail. */
const SAVE_ERROR_SNIPPETS = {
    SW6OIDC_SECRET_REQUIRED_FOR_ENDPOINT_CHANGE: 'errorSecretRequiredForEndpointChange',
    SW6OIDC_CLIENT_SECRET_REQUIRED: 'errorClientSecretRequired',
};

/** Default params per transform function (also for rows imported without params, F-N16). */
const TRANSFORM_DEFAULTS = {
    concat: { claims: [], separator: ' ' },
    split: { separator: ' ', index: 0 },
    prefix: { value: '' },
    regex_replace: { pattern: '', replacement: '' },
};

function isTechnicalClaim(key) {
    if (TECHNICAL_CLAIM_EXCLUSIONS.has(key)) {
        return true;
    }

    const dotIndex = key.indexOf('.');

    return dotIndex !== -1 && TECHNICAL_CLAIM_EXCLUSIONS.has(key.slice(0, dotIndex));
}

/**
 * Registered as a lazy factory (matching how Shopware's own core components
 * are registered), not a plain object, so that Mixin.getByName('notification')
 * below is only evaluated once Shopware actually builds this component -
 * never during this plugin's forced-early script execution on the login
 * screen (see Resources/views/administration/index.html.twig), where the
 * "notification" mixin isn't registered yet and this component is never
 * rendered anyway.
 */
Component.register('sw6oidc-provider-detail', () => {
    // Resolved here, not at module top level: core only registers the
    // component helpers (mapPropertyErrors, ...) in its init phase, which
    // runs after this bundle's forced-early execution on the login screen.
    const { mapPropertyErrors } = Component.getComponentHelper();

    return Promise.resolve({
        template,

        inject: ['repositoryFactory', 'acl', 'sw6oidcApiService'],

        mixins: [Mixin.getByName('notification')],

        data() {
            return {
                provider: null,
                isLoading: true,
                /** Only the newest loadEntity()/loadFormContext() response is applied (R3-F12). */
                entityRequestId: 0,
                formContextRequestId: 0,
                isLoadingConfiguration: false,
                isTestingConnection: false,
                connectionTestResult: null,
                isRunningLiveTest: false,
                liveTestReport: null,
                isRunningDiagnostics: false,
                /** Server message when disabling admin password login would lock out unbound admins */
                lockoutConfirmation: null,
                /** The confirmation needs a fresh re-authentication (R3-M22). */
                lockoutVerifying: false,
                /** Issuer change with connected accounts: the server's message (R3-M9). */
                issuerChangeConfirmation: null,
                /** true = keep the accounts connected, false = disconnect; set while verifying */
                issuerChangeRebind: null,
                /** Discovery URL as loaded: save re-discovers only when it changed (F-M7) */
                loadedWellKnownConfigUrl: null,
                /** Live test popup, to verify where results come from (F-M9) */
                liveTestPopup: null,
                /** GET provider/form-context */
                formContext: { postLogoutLandingUrls: [], webhookConfigured: false },
                /** "Remove webhook" was clicked: save sends null (F-N6) */
                removeWebhook: false,
                /** OidcDiagnosticsController response for this provider */
                diagnostics: null,
                /** @type {Record<string, unknown>} claims received on the last live login test, keyed by claim name */
                liveTestClaims: {},
                // Fixed widths of the two type columns, wide enough for the
                // longest (German) option label.
                attributeTypeColumnWidth: '280px',
                mappingTypeColumnWidth: '260px',
            };
        },

        metaInfo() {
            return {
                title: this.$createTitle(this.identifier),
            };
        },

        computed: {
            // Field-level violations from Sw6OidcProviderWriteGuardSubscriber (SSRF, lockout guard).
            ...mapPropertyErrors('provider', [
                'clientSecret',
                'wellKnownConfigUrl',
                'authorizeEndpoint',
                'accessTokenEndpoint',
                'userInfoEndpoint',
                'jwksEndpoint',
                'endSessionEndpoint',
                'postLogoutUrl',
                'healthAlertWebhookUrl',
                'revocationEndpoint',
                'disableNonOidcCustomerLogin',
                'disableNonOidcAdminLogin',
                // Trust fields: SW6OIDC_SUPERADMIN_REQUIRED shows on the field (plan F-2).
                'issuer',
                'clientId',
                'scope',
                'publicClient',
                'loginType',
                'allowSuperadminGroupMapping',
                'autoCreateAdmin',
                'defaultAclRoleId',
                'linkExistingAccounts',
                'requireEmailVerified',
                'base64Claims',
                'groupAttribute',
            ]),

            /**
             * client_secret is write-only over the API (encrypted at rest, never
             * returned), so an existing provider's form starts with it empty —
             * only required when creating, and a blank value keeps the stored one.
             */
            isNewProvider() {
                return !this.provider || this.provider.isNew();
            },

            identifier() {
                return this.provider ? (this.provider.displayName || this.provider.appName) : '';
            },

            providerRepository() {
                return this.repositoryFactory.create('sw6oidc_provider');
            },

            /**
             * EntityCollection itself has no `.repository` — a nested
             * association's own repository has to be created explicitly via
             * `entity`/`source` off the collection (Shopware's documented
             * pattern, e.g. `this.product.media.entity`/`.source` in core), then
             * used to `.create()` a new row before `.add()`-ing it to the
             * collection.
             */
            attributeMappingRepository() {
                return this.repositoryFactory.create(this.provider.attributeMappings.entity, this.provider.attributeMappings.source);
            },

            roleMappingRepository() {
                return this.repositoryFactory.create(this.provider.roleMappings.entity, this.provider.roleMappings.source);
            },

            accessControlRuleRepository() {
                return this.repositoryFactory.create(this.provider.accessControlRules.entity, this.provider.accessControlRules.source);
            },

            /** Sw6OidcAccessControlRuleDefinition::OPERATORS */
            operatorOptions() {
                return ['eq', 'neq', 'contains', 'not_contains', 'ends_with', 'email_domain', 'exists', 'not_exists'].map((value) => ({
                    value,
                    label: this.$t(`sw6oidc.provider.detail.operators.${value}`),
                }));
            },

            /**
             * Claim keys from the last live test with list indexes collapsed
             * (`groups.0`, `groups.1` → `groups`), since access rules match
             * list claims by membership. Technical claims stay in: `iss`/`aud`/
             * `amr` are legitimate things to gate on.
             */
            accessControlClaimKeys() {
                const keys = Object.keys(this.liveTestClaims ?? {}).map((key) => key.replace(/\.\d+(?=\.|$).*$/, ''));

                return [...new Set(keys)].sort();
            },

            /**
             * The shared post-logout landing (PostLogoutController) on a
             * storefront domain — the admin origin usually isn't one (F-N15).
             */
            postLogoutLandingUrl() {
                return this.formContext.postLogoutLandingUrls[0] ?? '';
            },

            /** Viewers see the page read-only (F-N8). */
            canEdit() {
                return this.isNewProvider ? this.acl.can('sw6oidc_provider.creator') : this.acl.can('sw6oidc_provider.editor');
            },

            /**
             * Endpoints, issuer, scope, superadmin mapping and the other
             * trust-relevant settings need a superadmin (R3-H4); the server
             * refuses them for everyone else.
             */
            isSuperadmin() {
                return Shopware.Store.get('session').currentUser?.admin === true;
            },

            /**
             * The fields of ProviderTrustGuardSubscriber::TRUST_FIELDS: only a
             * superadmin may change them (plan F-2).
             */
            canEditTrust() {
                return this.canEdit && this.isSuperadmin;
            },

            /** ProviderTrustGuardSubscriber::servesAdmins(): every login type but "customer". */
            servesAdmins() {
                return this.provider?.loginType !== 'customer';
            },

            /** Access rules of a provider that serves the Administration need a superadmin. */
            canEditAccessControl() {
                return this.canEdit && (this.isSuperadmin || !this.servesAdmins);
            },

            webhookConfigured() {
                return !this.removeWebhook && (this.formContext.webhookConfigured || !!this.diagnostics?.alerting?.webhookConfigured);
            },

            canRunLiveTest() {
                return !!(this.provider && this.provider.id && this.$route.params.id !== undefined);
            },

            // Same presentation as the "OIDC Provider" bind date (sw6oidc-user-provider-info).
            formattedLastTestAt() {
                return this.provider?.lastTestAt ? Shopware.Utils.format.date(this.provider.lastTestAt) : '';
            },

            attributeTypeOptions() {
                return [
                    'email', 'username', 'firstname', 'lastname', 'birthday', 'gender', 'phone',
                    'locale', 'zoneinfo', 'picture',
                    'billing_street', 'billing_zipcode', 'billing_city', 'billing_state', 'billing_country', 'billing_phone',
                    'shipping_street', 'shipping_zipcode', 'shipping_city', 'shipping_state', 'shipping_country', 'shipping_phone',
                ].map((value) => ({ value, label: this.$t(`sw6oidc.provider.detail.attributeType.${value}`) }));
            },

            mappingTypeOptions() {
                return ['admin_role', 'customer_group', 'superadmin'].map((value) => ({
                    value,
                    label: this.$t(`sw6oidc.provider.detail.mappingType.${value}`),
                }));
            },

            loginTypeOptions() {
                return ['both', 'customer', 'admin'].map((value) => ({
                    value,
                    label: this.$t(`sw6oidc.provider.detail.loginType.${value}`),
                }));
            },

            logoutStyleOptions() {
                return ['standard', 'authelia_forward_auth'].map((value) => ({
                    value,
                    label: this.$t(`sw6oidc.provider.detail.logoutStyle.${value}`),
                }));
            },

            clientAuthMethodOptions() {
                return ['client_secret_basic', 'client_secret_post'].map((value) => ({
                    value,
                    label: this.$t(`sw6oidc.provider.detail.clientAuthMethod.${value}`),
                }));
            },

            pkceFlowOptions() {
                return ['S256', 'plain'].map((value) => ({ value, label: value }));
            },

            base64Claims: {
                get() {
                    return Array.isArray(this.provider?.base64Claims) ? this.provider.base64Claims : [];
                },
                set(value) {
                    this.provider.base64Claims = (value ?? []).map((claim) => String(claim).trim()).filter((claim) => claim !== '');
                },
            },

            /**
             * Mirrors AdminProvisioningService::findOrCreateAdmin()'s own
             * refusal condition — warn here, before it fails a real login, that
             * a resolvable ACL role (or an active superadmin group mapping) is
             * required to JIT-create an admin.
             */
            adminProvisioningWarning() {
                if (!this.provider?.autoCreateAdmin || this.provider.defaultAclRoleId) {
                    return false;
                }

                const hasRoleMapping = this.provider.roleMappings?.some((mapping) => mapping.mappingType === 'admin_role');
                const hasActiveSuperadminMapping = this.provider.allowSuperadminGroupMapping
                    && this.provider.roleMappings?.some((mapping) => mapping.mappingType === 'superadmin');

                return !hasRoleMapping && !hasActiveSuperadminMapping;
            },

            /**
             * Claim names actually received on the most recent live login test —
             * the only source for the attribute-mapping picker (no static
             * "common claims" list): showing a claim this specific IdP doesn't
             * actually send would just be misleading. Empty until a live test
             * has been run at least once. Excludes protocol/token-metadata
             * claims (see TECHNICAL_CLAIM_EXCLUSIONS/isTechnicalClaim) — an
             * IdP's raw response always includes these, but they're never a
             * sensible attribute-mapping target.
             */
            discoveredClaimKeys() {
                return Object.keys(this.liveTestClaims ?? {}).filter((key) => !isTechnicalClaim(key));
            },

            /**
             * sw-single-select's own option shape.
             */
            claimSelectOptions() {
                return this.discoveredClaimKeys.map((key) => ({ value: key, label: key }));
            },

            /**
             * AttributeTransformer::FUNCTIONS, plus "none" (null).
             */
            transformFunctionOptions() {
                return [
                    { value: null, label: this.$t('sw6oidc.provider.detail.transform.none') },
                    ...['concat', 'split', 'prefix', 'regex_replace'].map((fn) => ({
                        value: fn,
                        label: this.$t(`sw6oidc.provider.detail.transform.functions.${fn}`),
                    })),
                ];
            },
        },

        watch: {
            // Navigating between providers (or to the saved new one) reuses this component (F-M10).
            '$route.params.id'(newId, oldId) {
                if (newId !== oldId) {
                    this.createdComponent();
                }
            },
        },

        created() {
            this.createdComponent();
        },

        mounted() {
            window.addEventListener('message', this.onTestResultMessage);
        },

        beforeUnmount() {
            window.removeEventListener('message', this.onTestResultMessage);
        },

        methods: {
            /**
             * Translated message for a connection-test check / live-test step:
             * fixed outcomes carry a messageKey (+ params), while dynamic ones
             * (exception messages from the IdP/HTTP layer) only have the
             * English `detail`, shown as-is.
             */
            testResultMessage(entry) {
                const key = `sw6oidc.provider.detail.testMessage.${entry.messageKey}`;

                // A key from a newer backend without a snippet falls back to the detail (R3-F16).
                if (entry.messageKey && this.$te(key)) {
                    return this.$t(key, entry.messageParams ?? {});
                }

                return entry.detail ?? entry.messageKey ?? '';
            },

            /**
             * Translation of a server-provided code, or the code itself when no
             * snippet exists for it (new codes from a newer backend).
             */
            snippetOr(key, fallback) {
                return this.$te(key) ? this.$t(key) : String(fallback ?? '');
            },

            /** Meteor mt-badge variants (R3-F15). */
            testStatusVariant(status) {
                return { pass: 'positive', warning: 'attention', skipped: 'neutral' }[status] ?? 'critical';
            },

            /**
             * Role mappings that grant an Administration role or superadmin
             * need a superadmin, also when they are changed away from that
             * type (the server checks the stored type too).
             */
            isPrivilegedRoleMapping(item) {
                const privileged = ['admin_role', 'superadmin'];

                return privileged.includes(item.mappingType) || privileged.includes(item.getOrigin?.()?.mappingType);
            },

            canEditRoleMapping(item) {
                return this.canEdit && (this.isSuperadmin || !this.isPrivilegedRoleMapping(item));
            },

            /** Non-superadmins can only add customer group rows. */
            mappingTypeOptionsFor(item) {
                if (this.isSuperadmin || this.isPrivilegedRoleMapping(item)) {
                    return this.mappingTypeOptions;
                }

                return this.mappingTypeOptions.filter((option) => option.value === 'customer_group');
            },

            /** Email/username mappings decide which account a login resolves to. */
            isIdentityAttributeMapping(item) {
                const identity = ['email', 'username'];

                return identity.includes(item.attributeType) || identity.includes(item.getOrigin?.()?.attributeType);
            },

            canEditAttributeMapping(item) {
                return this.canEdit && (this.isSuperadmin || !this.servesAdmins || !this.isIdentityAttributeMapping(item));
            },

            attributeTypeOptionsFor(item) {
                if (this.isSuperadmin || !this.servesAdmins || this.isIdentityAttributeMapping(item)) {
                    return this.attributeTypeOptions;
                }

                return this.attributeTypeOptions.filter((option) => !['email', 'username'].includes(option.value));
            },

            createdComponent() {
                this.diagnostics = null;
                this.liveTestReport = null;
                this.connectionTestResult = null;
                this.removeWebhook = false;
                this.loadFormContext(this.$route.params.id ?? null);

                if (this.$route.params.id) {
                    this.loadEntity(this.$route.params.id);

                    return;
                }

                // A provider still loading from before must not replace the new one.
                this.entityRequestId += 1;
                this.loadedWellKnownConfigUrl = null;
                this.liveTestClaims = {};

                this.provider = this.providerRepository.create(Shopware.Context.api);
                this.provider.scope = 'openid profile email';
                this.provider.pkceFlow = 'S256';
                this.provider.base64Claims = [];
                this.provider.groupAttribute = 'groups';
                this.provider.loginType = 'both';
                this.provider.isActive = true;
                this.provider.autoCreateCustomer = true;
                this.provider.httpTimeout = 30;
                this.provider.jwksCacheTtl = 86400;
                this.isLoading = false;
            },

            async loadFormContext(providerId) {
                const requestId = ++this.formContextRequestId;
                let formContext = { postLogoutLandingUrls: [], webhookConfigured: false };

                try {
                    const context = await this.sw6oidcApiService.get('_action/sw6oidc/provider/form-context', {
                        params: providerId ? { providerId } : {},
                    });
                    formContext = {
                        postLogoutLandingUrls: Array.isArray(context.postLogoutLandingUrls) ? context.postLogoutLandingUrls : [],
                        webhookConfigured: !!context.webhookConfigured,
                    };
                } catch {
                    // Defaults above.
                }

                // Fast A -> B navigation: A's answer must not land on B (R3-F12).
                if (requestId === this.formContextRequestId) {
                    this.formContext = formContext;
                }
            },

            loadEntity(id) {
                const requestId = ++this.entityRequestId;
                this.isLoading = true;
                const criteria = new Criteria();
                criteria.addAssociation('attributeMappings');
                criteria.addAssociation('roleMappings');
                criteria.addAssociation('accessControlRules');

                return this.providerRepository.get(id, Shopware.Context.api, criteria).then((entity) => {
                    // Fast A -> B navigation: A's entity must not replace B (R3-F12).
                    if (requestId !== this.entityRequestId) {
                        return;
                    }

                    this.provider = entity;
                    this.loadedWellKnownConfigUrl = entity.wellKnownConfigUrl;
                    entity.attributeMappings.forEach((mapping) => {
                        if (mapping.transformFunction && !mapping.transformParams) {
                            mapping.transformParams = { ...TRANSFORM_DEFAULTS[mapping.transformFunction] };
                        }
                    });
                    // Seeds the claim picker from whatever the last live login
                    // test actually observed, persisted server-side precisely so
                    // it survives a reload — this in-memory state otherwise has
                    // nowhere else to come from on a fresh page load.
                    this.liveTestClaims = entity.lastTestClaims && typeof entity.lastTestClaims === 'object'
                        ? entity.lastTestClaims
                        : {};
                    this.isLoading = false;
                }).catch(() => {
                    if (requestId !== this.entityRequestId) {
                        return;
                    }

                    this.isLoading = false;
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.detail.loadError') });
                });
            },

            async onClickSave() {
                if (!this.canEdit) {
                    return;
                }

                this.isLoading = true;

                // Only when the discovery URL changed: an unchanged one would
                // overwrite deliberately edited endpoints on every save (F-M7).
                if (this.provider.wellKnownConfigUrl && this.provider.wellKnownConfigUrl !== this.loadedWellKnownConfigUrl) {
                    // Best-effort re-discovery on every save: apply whatever the
                    // IdP returns, but never block the save on it — an admin who
                    // intentionally kept manually-entered endpoints shouldn't be
                    // locked out of saving just because the well-known URL is
                    // temporarily unreachable.
                    try {
                        await this.discoverAndApply(this.provider.wellKnownConfigUrl);
                    } catch (exception) {
                        this.createNotificationWarning({
                            title: this.$t('sw6oidc.provider.detail.discoverySaveWarningTitle'),
                            message: exception.message || this.$t('sw6oidc.provider.detail.discoveryError'),
                        });
                    }
                }

                // A blank secret means "keep the stored one" (or, for a public
                // client, "none") — don't send the empty string (it would fail
                // NotBlank). The server requires it for confidential clients.
                if (!this.provider.clientSecret) {
                    this.provider.clientSecret = undefined;
                }

                // Same for the write-only webhook URL (blank = keep the stored
                // one), unless "Remove webhook" was clicked (F-N6).
                if (this.removeWebhook) {
                    this.provider.healthAlertWebhookUrl = null;
                } else if (!this.provider.healthAlertWebhookUrl) {
                    this.provider.healthAlertWebhookUrl = undefined;
                }

                return this.providerRepository.save(this.provider, Shopware.Context.api).then(() => {
                    this.isLoading = false;
                    this.createNotificationSuccess({ message: this.$t('sw6oidc.provider.detail.saveSuccess') });
                    this.removeWebhook = false;
                    this.loadFormContext(this.provider.id);

                    if (this.$route.params.id === undefined) {
                        this.$router.push({ name: 'sw6oidc.provider.detail', params: { id: this.provider.id } });

                        return;
                    }

                    this.loadEntity(this.provider.id);
                }).catch((error) => {
                    this.isLoading = false;

                    const errors = error?.response?.data?.errors ?? [];
                    const unboundLockout = errors.find((entry) => entry.code === 'SW6OIDC_LOCKOUT_UNBOUND_USERS');

                    // Needs an explicit decision, not just an error toast.
                    if (unboundLockout && !this.isNewProvider) {
                        this.lockoutConfirmation = unboundLockout.detail;

                        return;
                    }

                    const issuerChange = errors.find((entry) => entry.code === 'SW6OIDC_ISSUER_CHANGE_CONFIRM');

                    if (issuerChange && !this.isNewProvider) {
                        this.issuerChangeConfirmation = issuerChange.detail;

                        return;
                    }

                    // Surface the server's own violation messages (SSRF block,
                    // lockout guard, ...) instead of only a generic failure.
                    const details = [...new Set(errors
                        .map((entry) => (SAVE_ERROR_SNIPPETS[entry.code]
                            ? this.$t(`sw6oidc.provider.detail.${SAVE_ERROR_SNIPPETS[entry.code]}`)
                            : entry.detail))
                        .filter(Boolean))];

                    this.createNotificationError({
                        message: details.length
                            ? `${this.$t('sw6oidc.provider.detail.saveError')} ${details.join(' ')}`
                            : this.$t('sw6oidc.provider.detail.saveError'),
                    });
                });
            },

            onConfirmLockout() {
                this.lockoutConfirmation = null;
                this.lockoutVerifying = true;
            },

            async onLockoutVerified() {
                this.lockoutVerifying = false;

                try {
                    await this.sw6oidcApiService.post(`_action/sw6oidc/provider/${this.provider.id}/confirm-lockout`);
                } catch {
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.detail.saveError') });

                    return;
                }

                await this.onClickSave();
            },

            onDecideIssuerChange(rebind) {
                this.issuerChangeConfirmation = null;
                this.issuerChangeRebind = rebind;
            },

            async onIssuerChangeVerified() {
                const rebind = this.issuerChangeRebind;
                this.issuerChangeRebind = null;

                try {
                    await this.sw6oidcApiService.post(`_action/sw6oidc/provider/${this.provider.id}/confirm-issuer-change`, { rebind });
                } catch {
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.detail.saveError') });

                    return;
                }

                await this.onClickSave();
            },

            onRemoveWebhook() {
                this.removeWebhook = true;
                this.provider.healthAlertWebhookUrl = null;
            },

            async onClickLoadConfiguration() {
                this.isLoadingConfiguration = true;

                try {
                    const warnings = await this.discoverAndApply(this.provider.wellKnownConfigUrl);
                    this.createNotificationSuccess({ message: this.$t('sw6oidc.provider.detail.discoverySuccess') });

                    warnings.forEach((warning) => {
                        this.createNotificationWarning({ message: warning });
                    });
                } catch (exception) {
                    this.createNotificationError({
                        message: exception.message || this.$t('sw6oidc.provider.detail.discoveryError'),
                    });
                } finally {
                    this.isLoadingConfiguration = false;
                }
            },

            /**
             * Fetches the well-known document and applies the returned endpoint
             * fields onto the in-memory (not-yet-saved) provider. Throws with a
             * human-readable message on failure so both callers (the explicit
             * "Load configuration" button and the save-time best-effort refresh)
             * can decide for themselves whether a failure should block anything.
             *
             * @return {Promise<string[]>} warnings returned alongside a successful fetch
             */
            async discoverAndApply(wellKnownConfigUrl) {
                if (!wellKnownConfigUrl) {
                    throw new Error(this.$t('sw6oidc.provider.detail.wellKnownConfigUrlRequired'));
                }

                let result;

                try {
                    result = await this.sw6oidcApiService.post('_action/sw6oidc/provider/discover', {
                        wellKnownConfigUrl,
                        httpTimeout: this.provider.httpTimeout,
                    });
                } catch (error) {
                    throw new Error(error?.response?.data?.message || this.$t('sw6oidc.provider.detail.discoveryError'));
                }

                DISCOVERED_ENDPOINT_FIELDS.forEach((key) => {
                    if (typeof result[key] === 'string' && result[key] !== '') {
                        this.provider[key] = result[key];
                    }
                });

                this.loadedWellKnownConfigUrl = wellKnownConfigUrl;

                return Array.isArray(result.warnings) ? result.warnings.filter((warning) => typeof warning === 'string') : [];
            },

            async onClickTestConnection() {
                this.isTestingConnection = true;
                this.connectionTestResult = null;

                try {
                    this.connectionTestResult = await this.sw6oidcApiService.post('_action/sw6oidc/provider/test-connection', {
                        wellKnownConfigUrl: this.provider.wellKnownConfigUrl,
                        authorizeEndpoint: this.provider.authorizeEndpoint,
                        accessTokenEndpoint: this.provider.accessTokenEndpoint,
                        userInfoEndpoint: this.provider.userInfoEndpoint,
                        jwksEndpoint: this.provider.jwksEndpoint,
                        endSessionEndpoint: this.provider.endSessionEndpoint,
                        revocationEndpoint: this.provider.revocationEndpoint,
                        issuer: this.provider.issuer,
                        clientId: this.provider.clientId,
                        clientSecret: this.provider.clientSecret,
                        providerId: this.isNewProvider ? null : this.provider.id,
                        publicClient: this.provider.publicClient,
                        httpTimeout: this.provider.httpTimeout,
                    });
                } catch (exception) {
                    // eslint-disable-next-line no-console
                    console.error('sw6oidc: connection test failed', exception);
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.detail.testConnectionError') });
                } finally {
                    this.isTestingConnection = false;
                }
            },

            async onClickRunLiveTest() {
                this.isRunningLiveTest = true;
                this.liveTestReport = null;

                // Opened synchronously in the click handler: a window.open()
                // after an await counts as a popup and gets blocked (F-M8).
                const popup = window.open('about:blank', 'sw6oidcTest', 'scrollbars=1,width=800,height=600');
                this.liveTestPopup = popup;

                try {
                    // The popup is rendered server-side, so it needs the UI locale passed along.
                    const result = await this.sw6oidcApiService.post(`_action/sw6oidc/provider/${this.provider.id}/test`, {
                        locale: Shopware.Store.get('session').currentLocale,
                    });

                    if (!popup || popup.closed) {
                        throw new Error(this.$t('sw6oidc.provider.detail.liveTestPopupBlocked'));
                    }

                    popup.location.href = result.authorizeUrl;
                } catch (exception) {
                    popup?.close();
                    this.createNotificationError({
                        message: exception?.response?.data?.message || exception.message || this.$t('sw6oidc.provider.detail.liveTestError'),
                    });
                } finally {
                    this.isRunningLiveTest = false;
                }
            },

            /**
             * Picks up the pass/fail report the test-callback popup posts back via
             * window.postMessage once the live login test completes, so the
             * detail page can show the outcome inline without the admin having to
             * manually close the popup and reload — reloading the entity also
             * happens here since the popup already persisted lastTestStatus/
             * lastTestAt server-side.
             */
            onTestResultMessage(event) {
                // Only from the popup this page opened (F-M9).
                if (
                    event.origin !== window.location.origin
                    || !this.liveTestPopup
                    || event.source !== this.liveTestPopup
                    || !event.data
                    || event.data.type !== 'sw6oidc-test-result'
                ) {
                    return;
                }

                this.liveTestReport = event.data;
                this.liveTestClaims = event.data.claims && typeof event.data.claims === 'object' ? event.data.claims : {};
                this.liveTestPopup = null;
                this.refreshTestStatus();
            },

            /**
             * Picks up lastTestStatus/lastTestAt the popup persisted, without
             * reloading the form and discarding unsaved edits (F-M9).
             */
            async refreshTestStatus() {
                if (!this.provider?.id) {
                    return;
                }

                try {
                    const stored = await this.providerRepository.get(this.provider.id, Shopware.Context.api);
                    this.provider.lastTestStatus = stored?.lastTestStatus ?? this.provider.lastTestStatus;
                    this.provider.lastTestAt = stored?.lastTestAt ?? this.provider.lastTestAt;
                } catch {
                    // Status display only.
                }
            },

            formatDate(value) {
                return value ? Shopware.Utils.format.date(value) : '';
            },

            async onClickRunDiagnostics() {
                this.isRunningDiagnostics = true;

                try {
                    this.diagnostics = await this.sw6oidcApiService.post(`_action/sw6oidc/provider/${this.provider.id}/diagnostics`);
                } catch (exception) {
                    // eslint-disable-next-line no-console
                    console.error('sw6oidc: diagnostics failed', exception);
                    this.createNotificationError({ message: this.$t('sw6oidc.provider.detail.diagnosticsError') });
                } finally {
                    this.isRunningDiagnostics = false;
                }
            },

            onAddAttributeMapping() {
                const mapping = this.attributeMappingRepository.create(Shopware.Context.api);
                mapping.providerId = this.provider.id;
                // Non-superadmins can't add identity mappings to a provider that serves admins.
                mapping.attributeType = this.isSuperadmin || !this.servesAdmins ? 'email' : 'firstname';
                mapping.attributeName = '';
                this.provider.attributeMappings.add(mapping);
            },

            /**
             * Params are function-specific, so switching the function starts from
             * that function's defaults instead of carrying stale keys over.
             */
            onTransformFunctionChange(item, transformFunction) {
                item.transformFunction = transformFunction || null;
                item.transformParams = transformFunction ? { ...TRANSFORM_DEFAULTS[transformFunction] } : null;
            },

            onRemoveAttributeMapping(item) {
                this.provider.attributeMappings.remove(item.id);
            },

            onAddRoleMapping() {
                const mapping = this.roleMappingRepository.create(Shopware.Context.api);
                mapping.providerId = this.provider.id;
                mapping.mappingType = 'customer_group';
                mapping.oidcGroup = '';
                mapping.aclRoleId = null;
                mapping.customerGroupId = null;
                mapping.sortOrder = this.provider.roleMappings.length;
                this.provider.roleMappings.add(mapping);
            },

            onRemoveRoleMapping(item) {
                this.provider.roleMappings.remove(item.id);
            },

            onAddAccessControlRule() {
                const rule = this.accessControlRuleRepository.create(Shopware.Context.api);
                rule.providerId = this.provider.id;
                rule.claimKey = '';
                rule.operator = 'eq';
                rule.value = '';
                rule.errorMessage = null;
                rule.sortOrder = this.provider.accessControlRules.length;
                this.provider.accessControlRules.add(rule);
            },

            onRemoveAccessControlRule(item) {
                this.provider.accessControlRules.remove(item.id);
            },

            /** exists/not_exists take no value; don't save a stale one. */
            onOperatorChange(item) {
                if (item.operator === 'exists' || item.operator === 'not_exists') {
                    item.value = null;
                }
            },

            isValuelessOperator(operator) {
                return operator === 'exists' || operator === 'not_exists';
            },

            /**
             * Clears whichever target FK no longer applies when a row switches
             * mapping type — otherwise a stale aclRoleId/customerGroupId from
             * before the switch would still get saved even though its picker is
             * no longer shown. 'superadmin' rows need neither target at all.
             */
            onMappingTypeChange(item) {
                if (item.mappingType === 'admin_role') {
                    item.customerGroupId = null;
                } else if (item.mappingType === 'customer_group') {
                    item.aclRoleId = null;
                } else {
                    item.aclRoleId = null;
                    item.customerGroupId = null;
                }
            },
        },
    });
});
