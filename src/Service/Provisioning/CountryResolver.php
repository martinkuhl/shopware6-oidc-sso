<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\OrFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\SuffixFilter;
use Shopware\Core\System\Country\Aggregate\CountryState\CountryStateCollection;
use Shopware\Core\System\Country\CountryCollection;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Resolves a free-text country claim (ISO-2, ISO-3, or a display name in any
 * shop language) to a Shopware `country` entity id — ISO passthrough first,
 * then a translated-name lookup, memoized per request. Also resolves a
 * free-text state/region claim to a `country_state` id, scoped to an
 * already-resolved country (short codes like "BY" collide across
 * countries, so a state can only ever be resolved once its country is
 * known).
 */
class CountryResolver implements ResetInterface
{
    /** @var array<string, string|null> */
    private array $memoized = [];

    /** @var array<string, string|null> */
    private array $stateMemoized = [];

    /**
     * @param EntityRepository<CountryCollection> $countryRepository
     * @param EntityRepository<CountryStateCollection> $countryStateRepository
     */
    public function __construct(
        private readonly EntityRepository $countryRepository,
        private readonly EntityRepository $countryStateRepository,
    ) {
    }

    /**
     * Long-running workers: the memo is per request (M20).
     */
    public function reset(): void
    {
        $this->memoized = [];
        $this->stateMemoized = [];
    }

    public function resolveCountryId(?string $countryClaim, Context $context): ?string
    {
        if ($countryClaim === null || trim($countryClaim) === '') {
            return null;
        }

        $key = mb_strtolower(trim($countryClaim));

        if (\array_key_exists($key, $this->memoized)) {
            return $this->memoized[$key];
        }

        return $this->memoized[$key] = $this->lookup(trim($countryClaim), $context);
    }

    public function resolveCountryStateId(?string $stateClaim, ?string $countryId, Context $context): ?string
    {
        if ($stateClaim === null || trim($stateClaim) === '' || $countryId === null) {
            return null;
        }

        $key = $countryId . ':' . mb_strtolower(trim($stateClaim));

        if (\array_key_exists($key, $this->stateMemoized)) {
            return $this->stateMemoized[$key];
        }

        return $this->stateMemoized[$key] = $this->lookupState(trim($stateClaim), $countryId, $context);
    }

    private function lookup(string $countryClaim, Context $context): ?string
    {
        $length = mb_strlen($countryClaim);

        if ($length === 2 || $length === 3) {
            $isoField = $length === 2 ? 'iso' : 'iso3';
            $criteria = new Criteria();
            $criteria->setLimit(1);
            $criteria->addFilter(new EqualsFilter($isoField, mb_strtoupper($countryClaim)));

            $id = $this->countryRepository->searchIds($criteria, $context)->firstId();

            if ($id !== null) {
                return $id;
            }
        }

        $nameCriteria = new Criteria();
        $nameCriteria->setLimit(1);
        $nameCriteria->addFilter(new EqualsFilter('translations.name', $countryClaim));

        return $this->countryRepository->searchIds($nameCriteria, $context)->firstId();
    }

    /**
     * Shopware seeds `short_code` as a country-prefixed ISO 3166-2 style code
     * (e.g. "DE-BY"), but an IdP's state/region claim just as plausibly sends
     * the bare subdivision code ("BY") or the full display name - tries an
     * exact match first, then a same-country "...-<claim>" suffix match,
     * before falling back to a translated name match.
     */
    private function lookupState(string $stateClaim, string $countryId, Context $context): ?string
    {
        $upperClaim = mb_strtoupper($stateClaim);

        $shortCodeCriteria = new Criteria();
        $shortCodeCriteria->setLimit(1);
        $shortCodeCriteria->addFilter(new EqualsFilter('countryId', $countryId));
        $shortCodeCriteria->addFilter(new OrFilter([
            new EqualsFilter('shortCode', $upperClaim),
            new SuffixFilter('shortCode', '-' . $upperClaim),
        ]));

        $id = $this->countryStateRepository->searchIds($shortCodeCriteria, $context)->firstId();

        if ($id !== null) {
            return $id;
        }

        $nameCriteria = new Criteria();
        $nameCriteria->setLimit(1);
        $nameCriteria->addFilter(new EqualsFilter('countryId', $countryId));
        $nameCriteria->addFilter(new EqualsFilter('translations.name', $stateClaim));

        return $this->countryStateRepository->searchIds($nameCriteria, $context)->firstId();
    }
}
