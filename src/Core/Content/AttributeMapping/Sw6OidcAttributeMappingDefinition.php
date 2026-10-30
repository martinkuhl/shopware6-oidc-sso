<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeTransformer;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\FkField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\ApiAware;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Choice;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\PrimaryKey;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IdField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\JsonField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\ManyToOneAssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StringField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\UpdatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\FieldCollection;

class Sw6OidcAttributeMappingDefinition extends EntityDefinition
{
    final public const ENTITY_NAME = 'sw6oidc_attribute_mapping';

    /** Identity + profile slots mapped from day one (see plan: full attribute parity). */
    public const TYPE_EMAIL = 'email';
    public const TYPE_USERNAME = 'username';
    public const TYPE_FIRSTNAME = 'firstname';
    public const TYPE_LASTNAME = 'lastname';
    public const TYPE_BIRTHDAY = 'birthday';
    public const TYPE_GENDER = 'gender';
    public const TYPE_PHONE = 'phone';
    public const TYPE_LOCALE = 'locale';
    public const TYPE_ZONEINFO = 'zoneinfo';
    public const TYPE_PICTURE = 'picture';
    public const TYPE_BILLING_STREET = 'billing_street';
    public const TYPE_BILLING_ZIPCODE = 'billing_zipcode';
    public const TYPE_BILLING_CITY = 'billing_city';
    public const TYPE_BILLING_STATE = 'billing_state';
    public const TYPE_BILLING_COUNTRY = 'billing_country';
    public const TYPE_BILLING_PHONE = 'billing_phone';
    public const TYPE_SHIPPING_STREET = 'shipping_street';
    public const TYPE_SHIPPING_ZIPCODE = 'shipping_zipcode';
    public const TYPE_SHIPPING_CITY = 'shipping_city';
    public const TYPE_SHIPPING_STATE = 'shipping_state';
    public const TYPE_SHIPPING_COUNTRY = 'shipping_country';
    public const TYPE_SHIPPING_PHONE = 'shipping_phone';

    /** Every type AttributeMapper reads; anything else would be stored and silently ignored (R8-L27). */
    public const TYPES = [
        self::TYPE_EMAIL, self::TYPE_USERNAME, self::TYPE_FIRSTNAME, self::TYPE_LASTNAME, self::TYPE_BIRTHDAY,
        self::TYPE_GENDER, self::TYPE_PHONE, self::TYPE_LOCALE, self::TYPE_ZONEINFO, self::TYPE_PICTURE,
        self::TYPE_BILLING_STREET, self::TYPE_BILLING_ZIPCODE, self::TYPE_BILLING_CITY, self::TYPE_BILLING_STATE,
        self::TYPE_BILLING_COUNTRY, self::TYPE_BILLING_PHONE,
        self::TYPE_SHIPPING_STREET, self::TYPE_SHIPPING_ZIPCODE, self::TYPE_SHIPPING_CITY, self::TYPE_SHIPPING_STATE,
        self::TYPE_SHIPPING_COUNTRY, self::TYPE_SHIPPING_PHONE,
    ];

    public function getEntityName(): string
    {
        return self::ENTITY_NAME;
    }

    public function getEntityClass(): string
    {
        return Sw6OidcAttributeMappingEntity::class;
    }

    public function getCollectionClass(): string
    {
        return Sw6OidcAttributeMappingCollection::class;
    }

    protected function defineFields(): FieldCollection
    {
        return new FieldCollection([
            (new IdField('id', 'id'))->addFlags(new ApiAware(), new PrimaryKey(), new Required()),
            (new FkField('provider_id', 'providerId', Sw6OidcProviderDefinition::class))->addFlags(new ApiAware(), new Required()),
            (new StringField('attribute_type', 'attributeType', 64))->addFlags(new ApiAware(), new Required(), new Choice(self::TYPES, true)),
            (new StringField('attribute_name', 'attributeName'))->addFlags(new ApiAware(), new Required()),
            (new StringField('transform_function', 'transformFunction', 32))->addFlags(new ApiAware(), new Choice(AttributeTransformer::FUNCTIONS, true)),
            (new JsonField('transform_params', 'transformParams'))->addFlags(new ApiAware()),
            new CreatedAtField(),
            new UpdatedAtField(),

            (new ManyToOneAssociationField('provider', 'provider_id', Sw6OidcProviderDefinition::class, 'id'))
                ->addFlags(new ApiAware()),
        ]);
    }
}
