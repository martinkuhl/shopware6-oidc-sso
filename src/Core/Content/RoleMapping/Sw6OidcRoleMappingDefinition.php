<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\RoleMapping;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupDefinition;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Choice;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IntField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

class Sw6OidcRoleMappingDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_role_mapping';

    public const MAPPING_TYPE_ADMIN_ROLE = 'admin_role';
    public const MAPPING_TYPE_CUSTOMER_GROUP = 'customer_group';
    /**
     * Grants full Shopware superadmin (bypasses ACL entirely) to any user
     * whose OIDC groups match — deliberately its own mapping type rather
     * than a flag on an `admin_role` row, so a superadmin grant is always a
     * distinct, explicit choice in the mapping grid, and additionally gated
     * behind the provider's own `allowSuperadminGroupMapping` toggle (see
     * AdminProvisioningService).
     */
    public const MAPPING_TYPE_SUPERADMIN = 'superadmin';

    public const MAPPING_TYPES = [self::MAPPING_TYPE_ADMIN_ROLE, self::MAPPING_TYPE_CUSTOMER_GROUP, self::MAPPING_TYPE_SUPERADMIN];

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return Sw6OidcRoleMappingEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcRoleMappingCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required()),
            (new FkField('provider_id', 'providerId', Sw6OidcProviderDefinition::class))->addFlags(new ApiAware(), new Required()),
            (new StringField('mapping_type', 'mappingType', 32))->addFlags(new ApiAware(), new Required(), new Choice(self::MAPPING_TYPES, true)),
            (new StringField('oidc_group', 'oidcGroup'))->addFlags(new ApiAware(), new Required()),
            (new FkField('acl_role_id', 'aclRoleId', AclRoleDefinition::class))->addFlags(new ApiAware()),
            (new FkField('customer_group_id', 'customerGroupId', CustomerGroupDefinition::class))->addFlags(new ApiAware()),
            (new IntField('sort_order', 'sortOrder'))->addFlags(new ApiAware()),
            new CreatedAtField(),
            new UpdatedAtField(),

            (new ManyToOneAssociationField('provider', 'provider_id', Sw6OidcProviderDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
            (new ManyToOneAssociationField('aclRole', 'acl_role_id', AclRoleDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
            (new ManyToOneAssociationField('customerGroup', 'customer_group_id', CustomerGroupDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
        ]);
    }
}
