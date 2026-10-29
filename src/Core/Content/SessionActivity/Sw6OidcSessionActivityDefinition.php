<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\SessionActivity;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateTimeField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

/**
 * One row per login (OIDC or Passkey, Storefront or Administration), closed
 * with the time and reason of its logout. A separate table on purpose:
 * sw6oidc_user_provider is the permanent one-row-per-account IdP binding.
 *
 * `session_key_hash` is sha256 of the local session key (context token /
 * access-token jti) — the raw value is a session credential and is never
 * stored. `registry_session_id` links to the Sw6OidcSessionRegistry entry of
 * OIDC logins. Both are internal and not ApiAware.
 */
class Sw6OidcSessionActivityDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_session_activity';

    public const LOGIN_METHOD_OIDC = 'oidc';
    public const LOGIN_METHOD_PASSKEY = 'passkey';

    public const LOGOUT_REASON_LOGOUT = 'logout';
    public const LOGOUT_REASON_BACKCHANNEL = 'backchannel';
    public const LOGOUT_REASON_FRONTCHANNEL = 'frontchannel';
    public const LOGOUT_REASON_FORCED = 'forced';

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return Sw6OidcSessionActivityEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcSessionActivityCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        // Audit log: written only by Sw6OidcSessionActivityRecorder in system
        // scope, never through the Admin API (N-M8; deletes: SessionActivityWriteGuardSubscriber).
        $systemOnly = new WriteProtected(Context::SYSTEM_SCOPE);

        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required(), $systemOnly),
            (new FkField('provider_id', 'providerId', Sw6OidcProviderDefinition::class))->addFlags(new ApiAware(), $systemOnly),
            (new StringField('user_type', 'userType', 16))->addFlags(new ApiAware(), new Required(), $systemOnly),
            (new IdField('user_id', 'userId'))->addFlags(new ApiAware(), new Required(), $systemOnly),
            // Internal, and only as `sha256:<hex>`: a `sid` ends sessions via front-channel logout, so it's a bearer capability (N-M5, R3-L40).
            (new StringField('sub', 'sub'))->addFlags($systemOnly),
            (new StringField('sid', 'sid'))->addFlags($systemOnly),
            (new StringField('login_method', 'loginMethod', 16))->addFlags(new ApiAware(), new Required(), $systemOnly),
            (new StringField('session_key_hash', 'sessionKeyHash', 64))->addFlags($systemOnly),
            (new StringField('registry_session_id', 'registrySessionId', 64))->addFlags($systemOnly),
            (new StringField('passkey_credential_hash', 'passkeyCredentialHash', 64))->addFlags($systemOnly),
            (new StringField('ip_address', 'ipAddress', 45))->addFlags(new ApiAware(), $systemOnly),
            (new StringField('user_agent', 'userAgent', 512))->addFlags(new ApiAware(), $systemOnly),
            (new DateTimeField('logged_in_at', 'loggedInAt'))->addFlags(new ApiAware(), new Required(), $systemOnly),
            (new DateTimeField('logged_out_at', 'loggedOutAt'))->addFlags(new ApiAware(), $systemOnly),
            (new StringField('logout_reason', 'logoutReason', 32))->addFlags(new ApiAware(), $systemOnly),
            new CreatedAtField(),
            new UpdatedAtField(),

            (new ManyToOneAssociationField('provider', 'provider_id', Sw6OidcProviderDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
        ]);
    }
}
