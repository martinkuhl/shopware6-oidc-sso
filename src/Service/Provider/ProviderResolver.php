<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provider;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsAnyFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Resolves sw6oidc_provider rows for the current request.
 */
class ProviderResolver
{
    /**
     * @param EntityRepository<Sw6OidcProviderCollection> $providerRepository
     */
    public function __construct(private readonly EntityRepository $providerRepository)
    {
    }

    /**
     * An active provider that serves this login type ('customer' or 'admin';
     * providers configured for 'both' serve either). A customer-only IdP must
     * never be usable for an Administration login, and vice versa.
     *
     * @throws ProviderNotFoundException
     */
    public function getActiveById(string $providerId, string $loginType, Context $context): Sw6OidcProviderEntity
    {
        // An empty or malformed id (`?providerId=`) would make Criteria throw (R3-L1).
        $provider = Uuid::isValid($providerId)
            ? $this->providerRepository->search(new Criteria([$providerId]), $context)->first()
            : null;

        if (
            !$provider instanceof Sw6OidcProviderEntity
            || !$provider->isActive()
            || !\in_array($provider->getLoginType(), [$loginType, 'both'], true)
        ) {
            throw new ProviderNotFoundException(sprintf('No active OIDC provider for login type "%s" found for id "%s".', $loginType, $providerId));
        }

        return $provider;
    }

    /**
     * Active providers configured with exactly this issuer — several
     * providers (one per client) may share an IdP, so callers pick by
     * audience. Used by Back-/Front-Channel Logout, where only the token's
     * `iss` identifies the provider.
     *
     * @return list<Sw6OidcProviderEntity>
     */
    public function findByIssuer(string $issuer, Context $context): array
    {
        if ($issuer === '') {
            return [];
        }

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('isActive', true));
        $criteria->addFilter(new EqualsFilter('issuer', $issuer));

        return array_values(array_filter(
            iterator_to_array($this->providerRepository->search($criteria, $context)->getEntities()),
            static fn (\Shopware\Core\Framework\DataAbstractionLayer\Entity $entity): bool => $entity instanceof Sw6OidcProviderEntity,
        ));
    }

    /**
     * @return Sw6OidcProviderEntity[]
     */
    public function getActiveProviders(string $loginType, Context $context): array
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('isActive', true));
        $criteria->addFilter(new EqualsAnyFilter('loginType', [$loginType, 'both']));
        $criteria->addSorting(new FieldSorting('sortOrder', FieldSorting::ASCENDING));

        return array_values(array_filter(
            iterator_to_array($this->providerRepository->search($criteria, $context)->getEntities()),
            static fn (\Shopware\Core\Framework\DataAbstractionLayer\Entity $entity): bool => $entity instanceof Sw6OidcProviderEntity,
        ));
    }

    /**
     * The providers whose SSO button should actually be shown for this login
     * type — deliberately a separate check from getActiveProviders():
     * "active" only reflects isActive/loginType, not the independent
     * show_customer_link/show_admin_link visibility toggle — a provider can
     * be active (and its login route fully reachable) while its button is
     * hidden from the login page, e.g. for an IdP an admin wants available
     * but not advertised. Only ever gates the button's visibility, not the
     * login route itself, which stays reachable by direct URL regardless.
     * Already sorted by sortOrder via getActiveProviders().
     *
     * @return Sw6OidcProviderEntity[]
     */
    public function getVisibleProviders(string $loginType, Context $context): array
    {
        return array_values(array_filter(
            $this->getActiveProviders($loginType, $context),
            static fn (Sw6OidcProviderEntity $provider): bool => $loginType === LoginType::Admin->value ? $provider->isShowAdminLink() : $provider->isShowCustomerLink(),
        ));
    }

    /**
     * SP-initiated login without an explicit ?provider_id= falls back to the
     * first active provider for this login type.
     *
     * @throws ProviderNotFoundException
     */
    public function resolveDefault(string $loginType, Context $context): Sw6OidcProviderEntity
    {
        $providers = $this->getActiveProviders($loginType, $context);

        if ($providers === []) {
            throw new ProviderNotFoundException(sprintf('No active OIDC provider is configured for login type "%s".', $loginType));
        }

        return $providers[0];
    }
}
