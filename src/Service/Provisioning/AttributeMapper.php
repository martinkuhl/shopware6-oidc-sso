<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition as Attr;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingEntity;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AttributeMappingCompletedEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\MissingEmailClaimException;
use Shopware\Core\Checkout\Customer\Service\EmailIdnConverter;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Maps a provider's sw6oidc_attribute_mapping rows against a flattened claims
 * response into a MappedProfile (identity, DOB, gender, phone, addresses).
 * Falls back to common OIDC
 * standard-claim names for the core identity fields when no explicit mapping
 * row is configured; address/DOB/gender/phone have no default claim key and
 * are simply left unmapped until configured.
 */
class AttributeMapper
{
    private const DEFAULT_CLAIM_KEYS = [
        Attr::TYPE_EMAIL => 'email',
        Attr::TYPE_USERNAME => 'preferred_username',
        Attr::TYPE_FIRSTNAME => 'given_name',
        Attr::TYPE_LASTNAME => 'family_name',
        Attr::TYPE_BIRTHDAY => 'birthdate',
        Attr::TYPE_GENDER => 'gender',
        Attr::TYPE_PHONE => 'phone_number',
        Attr::TYPE_LOCALE => 'locale',
        Attr::TYPE_ZONEINFO => 'zoneinfo',
        Attr::TYPE_PICTURE => 'picture',
    ];

    /**
     * @param EntityRepository<Sw6OidcAttributeMappingCollection> $attributeMappingRepository
     */
    public function __construct(
        private readonly EntityRepository $attributeMappingRepository,
        private readonly GenderMapper $genderMapper,
        private readonly AttributeTransformer $transformer,
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    /**
     * @param array<string, mixed> $flattenedClaims
     * @param string[]             $groups
     *
     * @throws MissingEmailClaimException
     */
    public function map(Sw6OidcProviderEntity $provider, array $flattenedClaims, array $groups, Context $context): MappedProfile
    {
        $mappings = $this->loadMappings($provider->getId(), $context);

        $read = function (string $attributeType) use ($flattenedClaims, $mappings): ?string {
            $mapping = $mappings[$attributeType] ?? null;
            $claimKey = $mapping?->getAttributeName() ?? self::DEFAULT_CLAIM_KEYS[$attributeType] ?? null;

            $raw = $claimKey !== null ? ($flattenedClaims[$claimKey] ?? null) : null;
            $value = \is_scalar($raw) ? trim((string) $raw) : null;

            if ($mapping === null) {
                return $value;
            }

            // Applied even when the claim itself is missing, so e.g. a concat
            // transform can still build a value from its other claims.
            return $this->transformer->apply(
                $mapping->getTransformFunction(),
                $mapping->getTransformParams() ?? [],
                $value,
                $flattenedClaims,
                \in_array($attributeType, [Attr::TYPE_EMAIL, Attr::TYPE_USERNAME], true),
            );
        };

        // Core stores international domains as punycode (EmailIdnConverter):
        // encoded first, `user@bücher.de` validates and matches the account (R3-L20).
        $email = $read(Attr::TYPE_EMAIL);
        $email = $email !== null ? EmailIdnConverter::encode(trim($email)) : null;

        if ($email === null || $email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new MissingEmailClaimException('The OIDC response did not contain a valid email claim.');
        }

        $billingAddress = new AddressProfile(
            street: $read(Attr::TYPE_BILLING_STREET),
            zipcode: $read(Attr::TYPE_BILLING_ZIPCODE),
            city: $read(Attr::TYPE_BILLING_CITY),
            state: $read(Attr::TYPE_BILLING_STATE),
            country: $read(Attr::TYPE_BILLING_COUNTRY),
            phone: $read(Attr::TYPE_BILLING_PHONE),
        );

        $shippingAddress = new AddressProfile(
            street: $read(Attr::TYPE_SHIPPING_STREET),
            zipcode: $read(Attr::TYPE_SHIPPING_ZIPCODE),
            city: $read(Attr::TYPE_SHIPPING_CITY),
            state: $read(Attr::TYPE_SHIPPING_STATE),
            country: $read(Attr::TYPE_SHIPPING_COUNTRY),
            phone: $read(Attr::TYPE_SHIPPING_PHONE),
        );

        $profile = new MappedProfile(
            email: $email,
            username: $read(Attr::TYPE_USERNAME),
            firstName: $read(Attr::TYPE_FIRSTNAME),
            lastName: $read(Attr::TYPE_LASTNAME),
            birthday: $read(Attr::TYPE_BIRTHDAY),
            salutationTechnicalName: $this->genderMapper->toSalutationTechnicalName($read(Attr::TYPE_GENDER)),
            phone: $read(Attr::TYPE_PHONE),
            locale: $read(Attr::TYPE_LOCALE),
            zoneinfo: $read(Attr::TYPE_ZONEINFO),
            picture: $read(Attr::TYPE_PICTURE),
            billingAddress: $billingAddress->isEmpty() ? null : $billingAddress,
            shippingAddress: $shippingAddress->isEmpty() ? null : $shippingAddress,
            groups: $groups,
        );

        $event = new AttributeMappingCompletedEvent($provider, $flattenedClaims, $profile, $context);
        $this->eventDispatcher->dispatch($event);
        $profile = $event->getProfile();

        // A listener may have replaced the profile — keep the email invariant.
        if (!filter_var(EmailIdnConverter::encode($profile->email), FILTER_VALIDATE_EMAIL)) {
            throw new MissingEmailClaimException('The mapped profile does not contain a valid email address.');
        }

        return $profile->truncatedToFieldLimits();
    }

    /**
     * @return array<string, Sw6OidcAttributeMappingEntity> attributeType => mapping row
     */
    private function loadMappings(string $providerId, Context $context): array
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('providerId', $providerId));

        $mappings = [];

        foreach ($this->attributeMappingRepository->search($criteria, $context)->getEntities() as $mapping) {
            $mappings[$mapping->getAttributeType()] = $mapping;
        }

        return $mappings;
    }
}
