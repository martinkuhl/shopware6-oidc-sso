<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

/**
 * Billing/shipping address claims, mapped separately from MappedProfile because
 * Shopware stores addresses as their own `customer_address` entities rather than
 * inline customer fields.
 */
final readonly class AddressProfile
{
    /** Limits of core's customer_address columns. */
    public const MAX_STREET_LENGTH = 255;
    public const MAX_ZIPCODE_LENGTH = 50;
    public const MAX_CITY_LENGTH = 255;
    public const MAX_PHONE_LENGTH = 40;

    public function __construct(
        public ?string $street = null,
        public ?string $zipcode = null,
        public ?string $city = null,
        /** free-text state/region claim value, resolved to a Shopware country-state id where possible */
        public ?string $state = null,
        /** ISO-2 code or display name, resolved to a Shopware country id by CountryResolver */
        public ?string $country = null,
        public ?string $phone = null,
    ) {
    }

    /**
     * @see MappedProfile::truncatedToFieldLimits()
     */
    public function truncatedToFieldLimits(): self
    {
        return new self(
            MappedProfile::fit($this->street, self::MAX_STREET_LENGTH),
            MappedProfile::fit($this->zipcode, self::MAX_ZIPCODE_LENGTH),
            MappedProfile::fit($this->city, self::MAX_CITY_LENGTH),
            $this->state,
            $this->country,
            MappedProfile::fit($this->phone, self::MAX_PHONE_LENGTH),
        );
    }

    public function isEmpty(): bool
    {
        return $this->street === null
            && $this->zipcode === null
            && $this->city === null
            && $this->state === null
            && $this->country === null
            && $this->phone === null;
    }
}
