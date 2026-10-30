<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

/**
 * Who the IdP says authenticated: the provider, the verified subject
 * (`iss` + `sub`, the only stable identifier) and whether the IdP vouches
 * for the mapped email (`email_verified`). Accounts are bound and looked up
 * by the subject; the email (MappedProfile) is only used to link a
 * pre-existing account once, under the provider's linking policy.
 */
final readonly class ExternalIdentity
{
    public function __construct(
        public string $providerId,
        public string $issuer,
        public string $subject,
        public bool $emailVerified,
    ) {
    }
}
