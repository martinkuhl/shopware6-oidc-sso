<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition as Attr;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingEntity;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Event\AttributeMappingCompletedEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeMapper;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeTransformer;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\MissingEmailClaimException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\GenderMapper;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\EventDispatcher\EventDispatcher;

#[CoversClass(AttributeMapper::class)]
final class AttributeMapperTest extends TestCase
{
    public function testMapsLocaleZoneinfoAndPictureUsingDefaultClaimKeys(): void
    {
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), new EventDispatcher());

        $profile = $mapper->map($this->provider(), [
            'email' => 'user@example.com',
            'locale' => 'de-DE',
            'zoneinfo' => 'Europe/Berlin',
            'picture' => 'https://idp.example.com/avatar.png',
        ], [], Context::createDefaultContext());

        self::assertSame('de-DE', $profile->locale);
        self::assertSame('Europe/Berlin', $profile->zoneinfo);
        self::assertSame('https://idp.example.com/avatar.png', $profile->picture);
    }

    #[RequiresPhpExtension('intl')]
    public function testInternationalDomainsAreStoredAsPunycodeLikeCore(): void
    {
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), new EventDispatcher());

        // FILTER_VALIDATE_EMAIL alone refused this, and core would never find the account (R3-L20).
        $profile = $mapper->map($this->provider(), ['email' => ' user@bücher.de '], [], Context::createDefaultContext());

        self::assertSame('user@xn--bcher-kva.de', $profile->email);
    }

    public function testOverlongValuesAreCutToTheColumnLimits(): void
    {
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), new EventDispatcher());

        // A WriteException on every login of this user before (R3-L21).
        $profile = $mapper->map($this->provider(), ['email' => 'user@example.com', 'given_name' => str_repeat('ä', 300)], [], Context::createDefaultContext());

        self::assertSame(255, mb_strlen((string) $profile->firstName));
    }

    public function testMapsLocaleZoneinfoAndPictureUsingConfiguredClaimKeyOverrides(): void
    {
        $providerId = Uuid::randomHex();

        $mapper = new AttributeMapper(
            $this->repositoryReturning([
                $this->mappingEntity($providerId, Attr::TYPE_LOCALE, 'user_locale'),
                $this->mappingEntity($providerId, Attr::TYPE_ZONEINFO, 'tz'),
                $this->mappingEntity($providerId, Attr::TYPE_PICTURE, 'avatar_url'),
            ]),
            new GenderMapper(),
            new AttributeTransformer(new NullLogger()),
            new EventDispatcher(),
        );

        $profile = $mapper->map($this->provider($providerId), [
            'email' => 'user@example.com',
            'user_locale' => 'en-GB',
            'tz' => 'America/New_York',
            'avatar_url' => 'https://idp.example.com/other-avatar.png',
        ], [], Context::createDefaultContext());

        self::assertSame('en-GB', $profile->locale);
        self::assertSame('America/New_York', $profile->zoneinfo);
        self::assertSame('https://idp.example.com/other-avatar.png', $profile->picture);
    }

    public function testLeavesLocaleZoneinfoAndPictureNullWhenClaimIsMissing(): void
    {
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), new EventDispatcher());

        $profile = $mapper->map($this->provider(), [
            'email' => 'user@example.com',
        ], [], Context::createDefaultContext());

        self::assertNull($profile->locale);
        self::assertNull($profile->zoneinfo);
        self::assertNull($profile->picture);
    }

    private function provider(?string $id = null): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId($id ?? Uuid::randomHex());

        return $provider;
    }

    public function testMappingCompletedListenerCanReplaceTheProfile(): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(AttributeMappingCompletedEvent::class, static function (AttributeMappingCompletedEvent $event): void {
            self::assertSame('corp-42', $event->getFlattenedClaims()['employee_id']);
            $event->setProfile(new MappedProfile($event->getProfile()->email, firstName: 'From listener'));
        });
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), $dispatcher);

        $profile = $mapper->map($this->provider(), ['email' => 'user@example.com', 'employee_id' => 'corp-42'], [], Context::createDefaultContext());

        self::assertSame('From listener', $profile->firstName);
    }

    public function testListenerCannotRemoveTheEmail(): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(AttributeMappingCompletedEvent::class, static function (AttributeMappingCompletedEvent $event): void {
            $event->setProfile(new MappedProfile('not-an-email'));
        });
        $mapper = new AttributeMapper($this->repositoryReturning([]), new GenderMapper(), new AttributeTransformer(new NullLogger()), $dispatcher);

        $this->expectException(MissingEmailClaimException::class);
        $mapper->map($this->provider(), ['email' => 'user@example.com'], [], Context::createDefaultContext());
    }

    public function testAppliesConfiguredTransforms(): void
    {
        $providerId = Uuid::randomHex();

        $mapper = new AttributeMapper(
            $this->repositoryReturning([
                $this->mappingEntity($providerId, Attr::TYPE_FIRSTNAME, 'name', AttributeTransformer::SPLIT, ['separator' => ' ', 'index' => 0]),
                $this->mappingEntity($providerId, Attr::TYPE_LASTNAME, 'name', AttributeTransformer::SPLIT, ['separator' => ' ', 'index' => -1]),
                // claim itself missing: concat still builds a value from its other claims
                $this->mappingEntity($providerId, Attr::TYPE_BILLING_STREET, 'street_missing', AttributeTransformer::CONCAT, ['claims' => ['street', 'house_no']]),
            ]),
            new GenderMapper(),
            new AttributeTransformer(new NullLogger()),
            new EventDispatcher(),
        );

        $profile = $mapper->map($this->provider($providerId), [
            'email' => 'user@example.com',
            'name' => 'Ada Lovelace',
            'street' => 'Main St',
            'house_no' => '5',
        ], [], Context::createDefaultContext());

        self::assertSame('Ada', $profile->firstName);
        self::assertSame('Lovelace', $profile->lastName);
        self::assertSame('Main St 5', $profile->billingAddress?->street);
    }

    /**
     * @param array<string, mixed>|null $transformParams
     */
    private function mappingEntity(
        string $providerId,
        string $attributeType,
        string $attributeName,
        ?string $transformFunction = null,
        ?array $transformParams = null,
    ): Sw6OidcAttributeMappingEntity {
        $entity = new Sw6OidcAttributeMappingEntity();
        $entity->setId(Uuid::randomHex());
        $entity->setProviderId($providerId);
        $entity->setAttributeType($attributeType);
        $entity->setAttributeName($attributeName);
        $entity->setTransformFunction($transformFunction);
        $entity->setTransformParams($transformParams);

        return $entity;
    }

    /**
     * @param Sw6OidcAttributeMappingEntity[] $entities
     */
    private function repositoryReturning(array $entities): EntityRepository
    {
        $collection = new Sw6OidcAttributeMappingCollection($entities);
        $apiAlias = $entities === [] ? Attr::ENTITY_NAME : $entities[0]->getApiAlias();

        $result = new EntitySearchResult(
            $apiAlias,
            \count($entities),
            $collection,
            null,
            new Criteria(),
            Context::createDefaultContext(),
        );

        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturn($result);

        return $repository;
    }
}
