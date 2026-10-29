<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\ExternalIdentity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsAnyFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\IdSearchResult;
use Shopware\Core\Framework\Uuid\Uuid;

#[CoversClass(UserProviderBindingService::class)]
final class UserProviderBindingServiceTest extends TestCase
{
    private const USER_TYPE = Sw6OidcUserProviderEntity::USER_TYPE_ADMIN;

    public function testGetBoundProviderIdReturnsNullWhenUnbound(): void
    {
        $service = new UserProviderBindingService($this->repositoryReturning(null));

        self::assertNull($service->getBoundProviderId(self::USER_TYPE, Uuid::randomHex(), Context::createDefaultContext()));
    }

    public function testGetBoundProviderIdReturnsBoundProviderAndFiltersByUserTypeAndUserId(): void
    {
        $userId = Uuid::randomHex();
        $providerId = Uuid::randomHex();
        $capturedCriteria = null;

        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())
            ->method('search')
            ->willReturnCallback(function (Criteria $criteria, Context $context) use (&$capturedCriteria, $userId, $providerId): EntitySearchResult {
                $capturedCriteria = $criteria;

                return $this->searchResult($this->binding($userId, $providerId), $criteria, $context);
            });

        $service = new UserProviderBindingService($repository);

        self::assertSame($providerId, $service->getBoundProviderId(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $userId, Context::createDefaultContext()));
        self::assertInstanceOf(Criteria::class, $capturedCriteria);
        self::assertEquals([
            new EqualsFilter('userType', Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER),
            new EqualsFilter('userId', $userId),
        ], $capturedCriteria->getFilters());
    }




    public function testBindCreatesSubjectBindingWhenUnbound(): void
    {
        $userId = Uuid::randomHex();
        $providerId = Uuid::randomHex();
        $context = Context::createDefaultContext();

        $repository = $this->repositoryReturning(null);
        $repository->expects(self::once())
            ->method('create')
            ->with(
                self::callback(static function (array $payload) use ($userId, $providerId): bool {
                    self::assertCount(1, $payload);
                    self::assertTrue(Uuid::isValid($payload[0]['id']));
                    unset($payload[0]['id']);
                    self::assertSame([
                        'userType' => self::USER_TYPE,
                        'userId' => $userId,
                        'providerId' => $providerId,
                        'issuer' => 'https://idp.example.com',
                        'issuerHash' => hash('sha256', 'https://idp.example.com'),
                        'sub' => 'subject-1',
                        'bindingScope' => Sw6OidcUserProviderEntity::GLOBAL_SCOPE,
                    ], $payload[0]);

                    return true;
                }),
                $context,
            );

        (new UserProviderBindingService($repository))->bind(self::USER_TYPE, $userId, $this->identity($providerId), $context);
    }

    public function testBindIsNoOpWhenTheSubjectIsAlreadyBoundToTheSameAccount(): void
    {
        $userId = Uuid::randomHex();
        $providerId = Uuid::randomHex();

        $repository = $this->repositoryReturning($this->binding($userId, $providerId, 'subject-1'));
        $repository->expects(self::never())->method('create');

        (new UserProviderBindingService($repository))->bind(self::USER_TYPE, $userId, $this->identity($providerId), Context::createDefaultContext());
    }

    public function testBindRefusesASubjectBoundToAnotherAccount(): void
    {
        $providerId = Uuid::randomHex();

        $repository = $this->repositoryReturning($this->binding(Uuid::randomHex(), $providerId, 'subject-1'));
        $repository->expects(self::never())->method('create');

        $this->expectException(SubjectAlreadyLinkedException::class);

        (new UserProviderBindingService($repository))->bind(self::USER_TYPE, Uuid::randomHex(), $this->identity($providerId), Context::createDefaultContext());
    }

    public function testConcurrentBindOfTheSameIdentityIsAccepted(): void
    {
        $userId = Uuid::randomHex();
        $providerId = Uuid::randomHex();
        $calls = 0;

        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context) use (&$calls, $userId, $providerId): EntitySearchResult {
            ++$calls;

            // First lookup (by subject) sees nothing; the re-read after the lost race sees the winner.
            return $this->searchResult($calls === 1 ? null : $this->binding($userId, $providerId, 'subject-1'), $criteria, $context);
        });
        $repository->method('create')->willThrowException($this->createStub(UniqueConstraintViolationException::class));

        (new UserProviderBindingService($repository))->bind(self::USER_TYPE, $userId, $this->identity($providerId), Context::createDefaultContext());

        self::assertSame(2, $calls);
    }

    public function testConcurrentBindOfADifferentIdentityIsRefused(): void
    {
        $userId = Uuid::randomHex();
        $calls = 0;

        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context) use (&$calls, $userId): EntitySearchResult {
            ++$calls;

            return $this->searchResult($calls === 1 ? null : $this->binding($userId, Uuid::randomHex(), 'other'), $criteria, $context);
        });
        $repository->method('create')->willThrowException($this->createStub(UniqueConstraintViolationException::class));

        $this->expectException(ProviderMismatchException::class);

        (new UserProviderBindingService($repository))->bind(self::USER_TYPE, $userId, $this->identity(Uuid::randomHex()), Context::createDefaultContext());
    }

    /**
     * R3-M9: the issuer is part of the identity; R3-M14: a channel-scoped
     * binding wins over the global one of the same subject.
     */
    public function testLookupFiltersOnIssuerAndPrefersTheChannelScope(): void
    {
        $providerId = Uuid::randomHex();
        $channel = Uuid::randomHex();
        $global = $this->binding(Uuid::randomHex(), $providerId, 'subject-1');
        $scoped = $this->binding(Uuid::randomHex(), $providerId, 'subject-1');
        $scoped->setBindingScope($channel);
        $captured = null;

        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context) use (&$captured, $global, $scoped): EntitySearchResult {
            $captured = $criteria;

            return new EntitySearchResult(Sw6OidcUserProviderDefinition::ENTITY_NAME, 2, new Sw6OidcUserProviderCollection([$global, $scoped]), null, $criteria, $context);
        });

        $service = new UserProviderBindingService($repository);

        self::assertSame($scoped->getUserId(), $service->findUserIdBySubject(self::USER_TYPE, $this->identity($providerId), Context::createDefaultContext(), $channel));
        self::assertInstanceOf(Criteria::class, $captured);
        self::assertContainsEquals(new EqualsFilter('issuerHash', hash('sha256', 'https://idp.example.com')), $captured->getFilters());
        self::assertContainsEquals(new EqualsAnyFilter('bindingScope', [$channel, Sw6OidcUserProviderEntity::GLOBAL_SCOPE]), $captured->getFilters());
    }

    public function testUnbindDeletesAllBindingRowsForUser(): void
    {
        $userId = Uuid::randomHex();
        $ids = [Uuid::randomHex(), Uuid::randomHex()];
        $context = Context::createDefaultContext();

        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())
            ->method('searchIds')
            ->willReturnCallback(function (Criteria $criteria, Context $ctx) use ($ids, $userId): IdSearchResult {
                self::assertEquals([
                    new EqualsFilter('userType', self::USER_TYPE),
                    new EqualsFilter('userId', $userId),
                ], $criteria->getFilters());

                return $this->idSearchResult($ids, $criteria, $ctx);
            });
        $repository->expects(self::once())
            ->method('delete')
            ->with([['id' => $ids[0]], ['id' => $ids[1]]], $context);

        (new UserProviderBindingService($repository))->unbind(self::USER_TYPE, $userId, $context);
    }

    public function testUnbindIsNoOpWhenUnbound(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('searchIds')
            ->willReturnCallback(fn (Criteria $criteria, Context $ctx): IdSearchResult => $this->idSearchResult([], $criteria, $ctx));
        $repository->expects(self::never())->method('delete');

        (new UserProviderBindingService($repository))->unbind(self::USER_TYPE, Uuid::randomHex(), Context::createDefaultContext());
    }

    private function binding(string $userId, string $providerId, ?string $sub = null): Sw6OidcUserProviderEntity
    {
        $entity = new Sw6OidcUserProviderEntity();
        $entity->setId(Uuid::randomHex());
        $entity->setUserType(self::USER_TYPE);
        $entity->setUserId($userId);
        $entity->setProviderId($providerId);
        $entity->setSub($sub);
        $entity->setIssuer('https://idp.example.com');
        $entity->setIssuerHash(UserProviderBindingService::issuerHash('https://idp.example.com'));

        return $entity;
    }

    private function identity(string $providerId): ExternalIdentity
    {
        return new ExternalIdentity($providerId, 'https://idp.example.com', 'subject-1', 'jane@example.com', true);
    }

    private function repositoryReturning(?Sw6OidcUserProviderEntity $binding): EntityRepository&\PHPUnit\Framework\MockObject\MockObject
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')
            ->willReturnCallback(fn (Criteria $criteria, Context $context): EntitySearchResult => $this->searchResult($binding, $criteria, $context));

        return $repository;
    }

    private function searchResult(?Sw6OidcUserProviderEntity $binding, Criteria $criteria, Context $context): EntitySearchResult
    {
        $entities = $binding === null ? [] : [$binding];

        return new EntitySearchResult(
            Sw6OidcUserProviderDefinition::ENTITY_NAME,
            \count($entities),
            new Sw6OidcUserProviderCollection($entities),
            null,
            $criteria,
            $context,
        );
    }

    /**
     * @param string[] $ids
     */
    private function idSearchResult(array $ids, Criteria $criteria, Context $context): IdSearchResult
    {
        return new IdSearchResult(
            \count($ids),
            array_map(static fn (string $id): array => ['primaryKey' => $id, 'data' => []], $ids),
            $criteria,
            $context,
        );
    }
}
