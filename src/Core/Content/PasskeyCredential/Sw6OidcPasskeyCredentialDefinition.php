<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential;

use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\DateTimeField;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Choice;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IntField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\LongTextField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

/**
 * One WebAuthn credential per admin/customer (see plan: mirrors m2oidc_passkey_credentials).
 * userType/userId is the same deliberately-polymorphic pattern as Sw6OidcUserProviderDefinition.
 *
 * A passkey login resolves to the account in `user_id`, so every field but
 * the nickname is writable in system scope only (R3-H2): the plugin's own
 * ceremony code writes in system scope, the Admin API can't re-point a key at
 * another account or plant one. TrustEntityWriteGuardSubscriber refuses
 * inserts outside system scope as well.
 */
class Sw6OidcPasskeyCredentialDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_passkey_credential';

    final public const USER_TYPES = ['admin', 'customer'];

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return Sw6OidcPasskeyCredentialEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcPasskeyCredentialCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('user_type', 'userType', 16))->addFlags(new ApiAware(), new Required(), new Choice(self::USER_TYPES, true), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new IdField('user_id', 'userId'))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('credential_id', 'credentialId', 1400))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('credential_id_hash', 'credentialIdHash', 64))->addFlags(new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new LongTextField('public_key', 'publicKey'))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new IntField('sign_count', 'signCount'))->addFlags(new ApiAware(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('user_handle', 'userHandle'))->addFlags(new ApiAware(), new Required(), new WriteProtected(Context::SYSTEM_SCOPE)),
            (new StringField('nickname', 'nickname'))->addFlags(new ApiAware()),
            (new DateTimeField('disabled_at', 'disabledAt'))->addFlags(new ApiAware(), new WriteProtected(Context::SYSTEM_SCOPE)),
            new CreatedAtField(),
            new UpdatedAtField(),
        ]);
    }
}
