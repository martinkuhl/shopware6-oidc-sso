<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Service\Provisioning\CountryResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\IdSearchResult;

#[CoversClass(CountryResolver::class)]
final class CountryResolverTest extends TestCase
{
    /**
     * R8-L9: a user-editable country claim must not resolve to a country the
     * shop deactivated; checkout would refuse such an address.
     */
    public function testOnlyActiveCountriesAreConsidered(): void
    {
        $searches = [];
        $countries = $this->createStub(EntityRepository::class);
        $countries->method('searchIds')->willReturnCallback(static function (Criteria $criteria, Context $context) use (&$searches): IdSearchResult {
            $searches[] = $criteria;

            return new IdSearchResult(0, [], $criteria, $context);
        });

        (new CountryResolver($countries, $this->createStub(EntityRepository::class)))->resolveCountryId('DE', Context::createDefaultContext());

        self::assertCount(2, $searches, 'ISO code, then name');

        foreach ($searches as $criteria) {
            $active = array_filter($criteria->getFilters(), static fn ($filter): bool => $filter instanceof EqualsFilter && $filter->getField() === 'active' && $filter->getValue() === true);
            self::assertCount(1, $active);
        }
    }
}
