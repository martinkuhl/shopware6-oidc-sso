<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\Provider;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Field\Sw6OidcEncryptedField;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupDefinition;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\BoolField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateTimeField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\AllowHtml;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\CascadeDelete;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Choice;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ResetOnClone;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IntField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\JsonField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ListField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\OneToManyAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

class Sw6OidcProviderDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_provider';

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    /** OIDC RP-Initiated Logout: id_token_hint, client_id, post_logout_redirect_uri, state. */
    public const LOGOUT_STYLE_STANDARD = 'standard';

    /** Authelia's forward-auth portal logout: `?rd=<return URL>` (R3-M3). */
    public const LOGOUT_STYLE_AUTHELIA_FORWARD_AUTH = 'authelia_forward_auth';

    public const LOGOUT_STYLES = [self::LOGOUT_STYLE_STANDARD, self::LOGOUT_STYLE_AUTHELIA_FORWARD_AUTH];

    /** Client authentication via the Authorization header (RFC 6749 §2.3.1). */
    public const CLIENT_AUTH_METHOD_BASIC = 'client_secret_basic';

    /** Client authentication via client_id/client_secret in the form body (RFC 6749 §2.3.1). */
    public const CLIENT_AUTH_METHOD_POST = 'client_secret_post';

    public const CLIENT_AUTH_METHODS = [self::CLIENT_AUTH_METHOD_BASIC, self::CLIENT_AUTH_METHOD_POST];

    public const PKCE_FLOWS = ['S256', 'plain'];

    /** Encryption purpose of client_secret (Sw6OidcEncryptedFieldSerializer::purpose()). */
    public const CLIENT_SECRET_PURPOSE = self::ENTITY_NAME . '.client_secret';
    public const LOGIN_TYPES = ['customer', 'admin', 'both'];
    public const MIN_HTTP_TIMEOUT = 1;
    public const MAX_HTTP_TIMEOUT = 60;
    public const MIN_JWKS_CACHE_TTL = 60;
    public const MAX_JWKS_CACHE_TTL = 86400;

    public function getEntityClass(): string
    {
        return Sw6OidcProviderEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcProviderCollection::class;
    }

    /**
     * Security-relevant defaults for new providers (also created by the
     * Administration, which would otherwise send the switches' falsy state).
     *
     * @return array<string, mixed>
     */
    public function getDefaults(): array
    {
        return [
            'requireEmailVerified' => true,
            'linkExistingAccounts' => false,
            'frontchannelAdminLogout' => false,
            'revokeSuperadminOnSso' => false,
            'logoutStyle' => self::LOGOUT_STYLE_STANDARD,
            'tokenEndpointAuthMethod' => self::CLIENT_AUTH_METHOD_BASIC,
            'revocationEndpointAuthMethod' => self::CLIENT_AUTH_METHOD_BASIC,
            'sortOrder' => 0,
            'httpTimeout' => 30,
            'jwksCacheTtl' => 86400,
        ];
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required()),
            (new StringField('app_name', 'appName'))->addFlags(new ApiAware(), new Required()),
            (new StringField('display_name', 'displayName'))->addFlags(new ApiAware()),
            (new StringField('client_id', 'clientId'))->addFlags(new ApiAware(), new Required()),
            // Encrypted at rest and write-only over the API: no ApiAware flag, so
            // Admin API reads never return it (writes still accept it). Optional,
            // because public clients have none; the write guard requires it for
            // confidential clients (R3-M23). Never copied by a clone: a clone
            // with new endpoints would otherwise send the stored secret there (R3-M4).
            (new Sw6OidcEncryptedField('client_secret', 'clientSecret', 1024))->addFlags(new AllowHtml(false), new ResetOnClone()),
            (new StringField('authorize_endpoint', 'authorizeEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('access_token_endpoint', 'accessTokenEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('token_endpoint_auth_method', 'tokenEndpointAuthMethod', 32))->addFlags(new ApiAware(), new Choice(self::CLIENT_AUTH_METHODS, true)),
            (new StringField('user_info_endpoint', 'userInfoEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('end_session_endpoint', 'endSessionEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('logout_style', 'logoutStyle', 32))->addFlags(new ApiAware(), new Choice(self::LOGOUT_STYLES, true)),
            (new StringField('post_logout_url', 'postLogoutUrl', 1024))->addFlags(new ApiAware()),
            (new StringField('revocation_endpoint', 'revocationEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('revocation_endpoint_auth_method', 'revocationEndpointAuthMethod', 32))->addFlags(new ApiAware(), new Choice(self::CLIENT_AUTH_METHODS, true)),
            (new StringField('jwks_endpoint', 'jwksEndpoint', 1024))->addFlags(new ApiAware()),
            (new StringField('issuer', 'issuer', 1024))->addFlags(new ApiAware()),
            (new StringField('well_known_config_url', 'wellKnownConfigUrl', 1024))->addFlags(new ApiAware()),
            (new StringField('scope', 'scope', 512))->addFlags(new ApiAware(), new Required()),
            // Strict: `s256` would break every login (R3-L43).
            (new StringField('pkce_flow', 'pkceFlow'))->addFlags(new ApiAware(), new Required(), new Choice(self::PKCE_FLOWS, true)),
            (new ListField('base64_claims', 'base64Claims', StringField::class))->addFlags(new ApiAware()),
            (new BoolField('public_client', 'publicClient'))->addFlags(new ApiAware()),
            (new StringField('group_attribute', 'groupAttribute'))->addFlags(new ApiAware(), new Required()),
            (new BoolField('auto_create_customer', 'autoCreateCustomer'))->addFlags(new ApiAware()),
            (new BoolField('auto_create_admin', 'autoCreateAdmin'))->addFlags(new ApiAware()),
            (new BoolField('disable_non_oidc_admin_login', 'disableNonOidcAdminLogin'))->addFlags(new ApiAware()),
            (new BoolField('disable_non_oidc_customer_login', 'disableNonOidcCustomerLogin'))->addFlags(new ApiAware()),
            (new BoolField('show_customer_link', 'showCustomerLink'))->addFlags(new ApiAware()),
            (new BoolField('show_admin_link', 'showAdminLink'))->addFlags(new ApiAware()),
            (new BoolField('is_active', 'isActive'))->addFlags(new ApiAware()),
            (new StringField('login_type', 'loginType'))->addFlags(new ApiAware(), new Required(), new Choice(self::LOGIN_TYPES, true)),
            (new IntField('sort_order', 'sortOrder'))->addFlags(new ApiAware(), new Required()),
            (new BoolField('sync_customer_profile_on_sso', 'syncCustomerProfileOnSso'))->addFlags(new ApiAware()),
            (new BoolField('sync_customer_address_on_sso', 'syncCustomerAddressOnSso'))->addFlags(new ApiAware()),
            (new BoolField('sync_customer_group_on_sso', 'syncCustomerGroupOnSso'))->addFlags(new ApiAware()),
            (new BoolField('sync_admin_profile_on_sso', 'syncAdminProfileOnSso'))->addFlags(new ApiAware()),
            (new BoolField('sync_admin_role_on_sso', 'syncAdminRoleOnSso'))->addFlags(new ApiAware()),
            (new BoolField('allow_superadmin_group_mapping', 'allowSuperadminGroupMapping'))->addFlags(new ApiAware()),
            (new BoolField('require_email_verified', 'requireEmailVerified'))->addFlags(new ApiAware()),
            (new BoolField('link_existing_accounts', 'linkExistingAccounts'))->addFlags(new ApiAware()),
            (new BoolField('frontchannel_admin_logout', 'frontchannelAdminLogout'))->addFlags(new ApiAware()),
            (new BoolField('revoke_superadmin_on_sso', 'revokeSuperadminOnSso'))->addFlags(new ApiAware()),
            // Bounded: 40000 overflowed the SMALLINT column, a negative TTL disabled the cache (R3-L43).
            (new IntField('http_timeout', 'httpTimeout', self::MIN_HTTP_TIMEOUT, self::MAX_HTTP_TIMEOUT))->addFlags(new ApiAware(), new Required()),
            (new IntField('jwks_cache_ttl', 'jwksCacheTtl', self::MIN_JWKS_CACHE_TTL, self::MAX_JWKS_CACHE_TTL))->addFlags(new ApiAware(), new Required()),
            (new StringField('last_test_status', 'lastTestStatus', 16))->addFlags(new ApiAware(), new Choice(['pass', 'fail'], true)),
            (new DateTimeField('last_test_at', 'lastTestAt'))->addFlags(new ApiAware()),
            (new JsonField('last_test_claims', 'lastTestClaims'))->addFlags(new ApiAware()),
            // Health alerting: the webhook URL usually embeds a token, so it is
            // encrypted and write-only like the client secret. The runtime
            // state is owned by HealthCheckAlertTaskHandler (written via DBAL).
            (new Sw6OidcEncryptedField('health_alert_webhook_url', 'healthAlertWebhookUrl', 1024))->addFlags(new AllowHtml(false), new ResetOnClone()),
            (new IntField('health_alert_failure_threshold', 'healthAlertFailureThreshold', 0, 1000))->addFlags(new ApiAware()),
            (new BoolField('health_alert_notify_on_recovery', 'healthAlertNotifyOnRecovery'))->addFlags(new ApiAware()),
            (new IntField('health_alert_consecutive_failures', 'healthAlertConsecutiveFailures'))->addFlags(new ApiAware(), new WriteProtected()),
            (new StringField('health_alert_last_status', 'healthAlertLastStatus', 16))->addFlags(new ApiAware(), new WriteProtected()),
            (new DateTimeField('health_alert_last_checked_at', 'healthAlertLastCheckedAt'))->addFlags(new ApiAware(), new WriteProtected()),
            (new DateTimeField('health_alert_first_failure_at', 'healthAlertFirstFailureAt'))->addFlags(new ApiAware(), new WriteProtected()),
            (new DateTimeField('health_alert_last_notified_at', 'healthAlertLastNotifiedAt'))->addFlags(new ApiAware(), new WriteProtected()),
            (new FkField('default_customer_group_id', 'defaultCustomerGroupId', CustomerGroupDefinition::class))->addFlags(new ApiAware()),
            (new FkField('default_acl_role_id', 'defaultAclRoleId', AclRoleDefinition::class))->addFlags(new ApiAware()),
            new CreatedAtField(),
            new UpdatedAtField(),

            (new OneToManyAssociationField('attributeMappings', Sw6OidcAttributeMappingDefinition::class, 'provider_id'))
                ->addFlags(new ApiAware(), new CascadeDelete()),
            (new OneToManyAssociationField('roleMappings', Sw6OidcRoleMappingDefinition::class, 'provider_id'))
                ->addFlags(new ApiAware(), new CascadeDelete()),
            (new OneToManyAssociationField('accessControlRules', Sw6OidcAccessControlRuleDefinition::class, 'provider_id'))
                ->addFlags(new ApiAware(), new CascadeDelete()),
            (new ManyToOneAssociationField('defaultCustomerGroup', 'default_customer_group_id', CustomerGroupDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
            (new ManyToOneAssociationField('defaultAclRole', 'default_acl_role_id', AclRoleDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
        ]);
    }
}
