<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

/**
 * Normalizes gender-claim string variants (including German locale) to a
 * Shopware `salutation` entity technical_name ('mr'/'mrs') — Shopware has no
 * plain "gender" field, salutation is the closest equivalent and is resolved
 * to a salutationId by CustomerProvisioningService::resolveSalutationId().
 */
class GenderMapper
{
    private const MALE_VALUES = ['male', 'm', '1', 'mann', 'männlich', 'mannlich', 'herr'];
    private const FEMALE_VALUES = ['female', 'f', '2', 'frau', 'weiblich', 'w'];

    public function toSalutationTechnicalName(?string $genderClaim): ?string
    {
        if ($genderClaim === null || $genderClaim === '') {
            return null;
        }

        $normalized = mb_strtolower(trim($genderClaim));

        if (\in_array($normalized, self::MALE_VALUES, true)) {
            return 'mr';
        }

        if (\in_array($normalized, self::FEMALE_VALUES, true)) {
            return 'mrs';
        }

        return null;
    }
}
