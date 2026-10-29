<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

/**
 * Claim values already resolved against a provider's sw6oidc_attribute_mapping
 * rows, ready to be written to a Shopware customer/user (+ address) entity.
 * Every field but email is optional, so no claim has to be configured.
 */
final readonly class MappedProfile
{
    /** customer/address/user first_name, last_name, username (core: 255) */
    public const MAX_NAME_LENGTH = 255;

    public function __construct(
        public string $email,
        public ?string $username = null,
        public ?string $firstName = null,
        public ?string $lastName = null,
        /** raw claim value, format expected YYYY-MM-DD */
        public ?string $birthday = null,
        /** normalized via GenderMapper before this DTO is built */
        public ?string $salutationTechnicalName = null,
        public ?string $phone = null,
        /** raw claim value, e.g. "de-DE" */
        public ?string $locale = null,
        /** raw claim value, IANA identifier, e.g. "Europe/Berlin" */
        public ?string $zoneinfo = null,
        /** raw claim value, a URL to the profile picture */
        public ?string $picture = null,
        public ?AddressProfile $billingAddress = null,
        public ?AddressProfile $shippingAddress = null,
        /** @var string[] */
        public array $groups = [],
    ) {
    }

    /**
     * A copy with every free-text value cut to the column it ends up in
     * (customer, address and user fields): a 300-character `given_name` must
     * not make every login of that user fail with a WriteException (R3-L21).
     */
    public function truncatedToFieldLimits(): self
    {
        return new self(
            $this->email,
            self::fit($this->username, self::MAX_NAME_LENGTH),
            self::fit($this->firstName, self::MAX_NAME_LENGTH),
            self::fit($this->lastName, self::MAX_NAME_LENGTH),
            $this->birthday,
            $this->salutationTechnicalName,
            self::fit($this->phone, AddressProfile::MAX_PHONE_LENGTH),
            $this->locale,
            $this->zoneinfo,
            $this->picture,
            $this->billingAddress?->truncatedToFieldLimits(),
            $this->shippingAddress?->truncatedToFieldLimits(),
            $this->groups,
        );
    }

    public static function fit(?string $value, int $maxLength): ?string
    {
        return $value !== null && mb_strlen($value) > $maxLength ? mb_substr($value, 0, $maxLength) : $value;
    }
}
