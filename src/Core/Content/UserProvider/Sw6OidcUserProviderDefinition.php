<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\UserProvider;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Choice;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

/**
 * Binds a Shopware `user` (admin) or `customer` id to an IdP identity: the
 * provider plus the subject (`iss` + `sub`) it authenticated. Logins look
 * accounts up by that subject; `sub` is NULL only on legacy bindings created
 * before subject binding existed (backfilled on the next verified login).
 *
 * A binding decides which account an IdP subject logs into, so every field
 * is writable in system scope only (R3-H3), and
 * TrustEntityWriteGuardSubscriber refuses inserts and deletes outside it.
 * UserProviderBindingService is the only writer.
 *
 * The key of a binding is provider + user type + issuer + subject + scope
 * (R3-M9, R3-M14): `issuer_hash` is sha256 of `issuer`, `binding_scope` the
 * sales channel of a channel-bound customer, else GLOBAL_SCOPE.
 */
class Sw6OidcUserProviderDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_user_provider';

    final public const USER_TYPES = ['admin', 'customer'];

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return Sw6OidcUserProviderEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcUserProviderCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('user_type', 'userType', 16))->addFlags(new ApiAware(), new Required(), new Choice(self::USER_TYPES, true), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new IdField('user_id', 'userId'))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new FkField('provider_id', 'providerId', Sw6OidcProviderDefinition::class))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('issuer', 'issuer', 2048))->addFlags(new ApiAware(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('sub', 'sub', 255))->addFlags(new ApiAware(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('issuer_hash', 'issuerHash', 64))->addFlags(new WriteProtected(Context::SYSTEM_SCOPE)),
            (new IdField('binding_scope', 'bindingScope'))->addFlags(new ApiAware(), new WriteProtected(Context::SYSTEM_SCOPE)),
            new CreatedAtField(),
            new UpdatedAtField(),

            (new ManyToOneAssociationField('provider', 'provider_id', Sw6OidcProviderDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
        ]);
    }
}
