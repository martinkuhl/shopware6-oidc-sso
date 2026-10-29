<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provider;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\Filter;

#[CoversClass(ProviderResolver::class)]
final class ProviderResolverTest extends TestCase
{
    private const PROVIDER_ID = '0190f1a2b3c47d5e8f9a0b1c2d3e4f50';

    public function testFindByIssuerFiltersActiveProvidersByExactIssuer(): void
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId(self::PROVIDER_ID);

        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())->method('search')->willReturnCallback(static function (Criteria $criteria, Context $context) use ($provider): EntitySearchResult {
            $filters = array_map(static function (Filter $filter): array {
                self::assertInstanceOf(EqualsFilter::class, $filter);

                return [$filter->getField(), $filter->getValue()];
            }, $criteria->getFilters());
            self::assertSame([['isActive', true], ['issuer', 'https://idp.example']], $filters);

            return new EntitySearchResult(Sw6OidcProviderDefinition::ENTITY_NAME, 1, new Sw6OidcProviderCollection([$provider]), null, $criteria, $context);
        });

        self::assertSame([$provider], (new ProviderResolver($repository))->findByIssuer('https://idp.example', Context::createDefaultContext()));
    }

    public function testEmptyIssuerNeverQueries(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('search');

        self::assertSame([], (new ProviderResolver($repository))->findByIssuer('', Context::createDefaultContext()));
    }

    /**
     * @return iterable<string, array{string, string, bool, bool}>
     */
    public static function loginTypeMatrix(): iterable
    {
        yield 'customer provider, customer login' => ['customer', 'customer', true, true];
        yield 'customer provider, admin login' => ['customer', 'admin', true, false];
        yield 'admin provider, customer login' => ['admin', 'customer', true, false];
        yield 'both, admin login' => ['both', 'admin', true, true];
        yield 'both, customer login' => ['both', 'customer', true, true];
        yield 'inactive' => ['both', 'admin', false, false];
    }

    #[DataProvider('loginTypeMatrix')]
    public function testGetActiveByIdEnforcesTheLoginType(string $providerType, string $loginType, bool $active, bool $expectFound): void
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId(self::PROVIDER_ID);
        $provider->setLoginType($providerType);
        $provider->setIsActive($active);

        $repository = $this->createStub(EntityRepository::class);
        $repository->method('search')->willReturnCallback(static fn (Criteria $criteria, Context $context): EntitySearchResult => new EntitySearchResult(
            Sw6OidcProviderDefinition::ENTITY_NAME,
            1,
            new Sw6OidcProviderCollection([$provider]),
            null,
            $criteria,
            $context,
        ));

        if (!$expectFound) {
            $this->expectException(ProviderNotFoundException::class);
        }

        self::assertSame($provider, (new ProviderResolver($repository))->getActiveById(self::PROVIDER_ID, $loginType, Context::createDefaultContext()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedIds(): iterable
    {
        yield 'empty' => [''];
        yield 'not a uuid' => ['p1'];
    }

    #[DataProvider('malformedIds')]
    public function testMalformedIdIsProviderNotFoundWithoutQuery(string $providerId): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('search');

        $this->expectException(ProviderNotFoundException::class);

        (new ProviderResolver($repository))->getActiveById($providerId, 'customer', Context::createDefaultContext());
    }
}
