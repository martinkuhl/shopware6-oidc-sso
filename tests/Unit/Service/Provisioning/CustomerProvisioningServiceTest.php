<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\CustomerAfterCreateEvent;
use MartinKuhl\Sw6Oidc\Event\CustomerBeforeCreateEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AddressProfile;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CountryResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\CustomerProvisioningService;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\CustomerProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\ExternalIdentity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\GroupMappingResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\IdentityResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupEntity;
use Shopware\Core\Checkout\Customer\CustomerCollection;
use Shopware\Core\Checkout\Customer\CustomerDefinition;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Payment\PaymentMethodEntity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\IdSearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\NumberRange\ValueGenerator\NumberRangeValueGeneratorInterface;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SalesChannel\SalesChannelEntity;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Symfony\Component\EventDispatcher\EventDispatcher;

#[CoversClass(CustomerProvisioningService::class)]
final class CustomerProvisioningServiceTest extends TestCase
{
    private bool $bindCustomersToSalesChannel = false;

    private bool $boundAccountWithEmailExists = false;

    private ?EventDispatcher $eventDispatcher = null;

    private const CUSTOMER_NUMBER = '10042';

    private EntityRepository&MockObject $customerRepository;

    private EntityRepository&MockObject $userProviderRepository;

    private GroupMappingResolver&MockObject $groupMappingResolver;

    private Context $context;

    private string $salesChannelId;

    private string $languageId;

    private string $currentCustomerGroupId;

    private string $paymentMethodId;

    private string $salesChannelCountryId;

    private string $germanyId;

    private string $bavariaId;

    private string $franceId;

    private string $mrSalutationId;

    private string $notSpecifiedSalutationId;

    /** @var CustomerEntity[] */
    private array $existingCustomers = [];

    private ?string $boundProviderId = null;


    private string $providerId = '';

    private string $subject = 'idp-subject-1';

    private bool $emailVerified = true;

    /** @var list<array<string, mixed>> */
    private array $bindingPayloads = [];

    protected function setUp(): void
    {
        $this->context = Context::createDefaultContext();
        $this->salesChannelId = Uuid::randomHex();
        $this->languageId = Uuid::randomHex();
        $this->currentCustomerGroupId = Uuid::randomHex();
        $this->paymentMethodId = Uuid::randomHex();
        $this->salesChannelCountryId = Uuid::randomHex();
        $this->germanyId = Uuid::randomHex();
        $this->bavariaId = Uuid::randomHex();
        $this->franceId = Uuid::randomHex();
        $this->mrSalutationId = Uuid::randomHex();
        $this->notSpecifiedSalutationId = Uuid::randomHex();

        $this->customerRepository = $this->createMock(EntityRepository::class);
        $this->customerRepository->method('search')->willReturnCallback(
            function (Criteria $criteria, Context $context): EntitySearchResult {
                if ($criteria->getIds() !== []) {
                    $customers = [];

                    foreach ($criteria->getIds() as $id) {
                        \assert(\is_string($id));
                        $customers[] = $this->customer($id, 'created@example.com');
                    }

                    return $this->customerResult($customers, $criteria, $context);
                }

                return $this->customerResult($this->existingCustomers, $criteria, $context);
            },
        );

        $this->userProviderRepository = $this->createMock(EntityRepository::class);
        $this->userProviderRepository->method('search')->willReturnCallback(
            function (Criteria $criteria, Context $context): EntitySearchResult {
                $entities = [];
                $filters = [];

                foreach ($criteria->getFilters() as $filter) {
                    if ($filter instanceof EqualsFilter) {
                        $filters[$filter->getField()] = $filter->getValue();
                    }
                }

                // The double holds legacy (subject-less) bindings only: a lookup by subject finds none.
                if ($this->boundProviderId !== null && !\array_key_exists('sub', $filters)) {
                    $binding = new Sw6OidcUserProviderEntity();
                    $binding->setId(Uuid::randomHex());
                    $binding->setUserType(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER);
                    $userId = $filters['userId'] ?? $this->existingCustomers[0]->getId();
                    \assert(\is_string($userId));
                    $binding->setUserId($userId);
                    $binding->setProviderId($this->boundProviderId);
                    $binding->setSub(null);
                    $entities[] = $binding;
                }

                return new EntitySearchResult(
                    Sw6OidcUserProviderDefinition::ENTITY_NAME,
                    \count($entities),
                    new Sw6OidcUserProviderCollection($entities),
                    null,
                    $criteria,
                    $context,
                );
            },
        );
        $this->userProviderRepository->method('create')->willReturnCallback(
            function (array $payloads): EntityWrittenContainerEvent {
                foreach ($payloads as $payload) {
                    $this->bindingPayloads[] = $payload;
                }

                return EntityWrittenContainerEvent::createWithWrittenEvents([], $this->context, []);
            },
        );

        $this->groupMappingResolver = $this->createMock(GroupMappingResolver::class);
    }

    public function testExistingCustomerBoundToDifferentProviderThrowsProviderMismatch(): void
    {
        $provider = $this->provider();
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];
        $this->boundProviderId = Uuid::randomHex();

        $this->customerRepository->expects(self::never())->method('update');
        $this->customerRepository->expects(self::never())->method('create');
        $this->userProviderRepository->expects(self::never())->method('create');

        $this->expectException(ProviderMismatchException::class);

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());
    }

    public function testExistingCustomerBoundToSameProviderIsReturnedWithoutRebinding(): void
    {
        $provider = $this->provider();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];
        $this->boundProviderId = $provider->getId();

        $this->userProviderRepository->expects(self::never())->method('create');
        $this->customerRepository->expects(self::never())->method('create');

        $result = $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($existing, $result);
    }

    public function testAnActiveEmailMatchWinsOverAnInactiveOne(): void
    {
        $provider = $this->provider();
        $inactive = $this->customer(Uuid::randomHex(), 'user@example.com');
        $inactive->setActive(false);
        $active = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$inactive, $active];
        $this->boundProviderId = $provider->getId();

        $result = $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        // R3-L26; an inactive-only match is still returned (and then can't log in), never skipped.
        self::assertSame($active, $result);
    }

    public function testExistingUnboundCustomerGetsBoundToProvider(): void
    {
        $provider = $this->provider();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];

        $this->customerRepository->expects(self::never())->method('create');

        $result = $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($existing, $result);
        self::assertCount(1, $this->bindingPayloads);
        self::assertSame(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $this->bindingPayloads[0]['userType']);
        self::assertSame($existing->getId(), $this->bindingPayloads[0]['userId']);
        self::assertSame($provider->getId(), $this->bindingPayloads[0]['providerId']);
    }

    public function testExistingCustomerIsNotLinkedByEmailUnlessTheProviderAllowsIt(): void
    {
        $provider = $this->provider();
        $provider->setLinkExistingAccounts(false);
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];

        $this->userProviderRepository->expects(self::never())->method('create');
        $this->customerRepository->expects(self::never())->method('create');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());
    }

    public function testLegacyBindingIsBackfilledWithTheSubject(): void
    {
        $provider = $this->provider();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];
        $this->boundProviderId = $provider->getId();

        $updates = [];
        $this->userProviderRepository->method('update')->willReturnCallback(
            function (array $payloads) use (&$updates): EntityWrittenContainerEvent {
                array_push($updates, ...$payloads);

                return EntityWrittenContainerEvent::createWithWrittenEvents([], $this->context, []);
            },
        );

        $result = $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($existing, $result);
        self::assertCount(1, $updates);
        self::assertSame($this->subject, $updates[0]['sub']);
    }

    public function testLooksUpNonGuestCustomerByEmail(): void
    {
        $provider = $this->provider();
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];

        $captured = null;
        $this->customerRepository = $this->createMock(EntityRepository::class);
        $this->customerRepository->method('search')->willReturnCallback(
            function (Criteria $criteria, Context $context) use (&$captured): EntitySearchResult {
                $captured = $criteria;

                return $this->customerResult($this->existingCustomers, $criteria, $context);
            },
        );

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertInstanceOf(Criteria::class, $captured);
        $filters = [];

        foreach ($captured->getFilters() as $filter) {
            self::assertInstanceOf(EqualsFilter::class, $filter);
            $filters[$filter->getField()] = $filter->getValue();
        }

        self::assertSame(['email' => 'user@example.com', 'guest' => false], $filters);
    }

    public function testExistingCustomerBoundToOtherSalesChannelIsIgnored(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateCustomer(false);

        $foreign = $this->customer(Uuid::randomHex(), 'user@example.com');
        $foreign->setBoundSalesChannelId(Uuid::randomHex());
        $this->existingCustomers = [$foreign];

        $this->expectException(CustomerProvisioningDeniedException::class);

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());
    }

    public function testExistingCustomerBoundToCurrentSalesChannelIsFound(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateCustomer(false);

        $own = $this->customer(Uuid::randomHex(), 'user@example.com');
        $own->setBoundSalesChannelId($this->salesChannelId);
        $this->existingCustomers = [$own];

        $result = $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($own, $result);
    }

    public function testExistingCustomerIsNotUpdatedWhenAllSyncTogglesAreOff(): void
    {
        $provider = $this->provider();
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];

        $this->groupMappingResolver->expects(self::never())->method('resolveCustomerGroupId');
        $this->customerRepository->expects(self::never())->method('update');

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());
    }

    public function testProfileSyncAppliesOnlyProfileFields(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];

        $this->groupMappingResolver->expects(self::never())->method('resolveCustomerGroupId');
        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertSame($existing->getId(), $payload->value['id']);
        self::assertSame('Jane', $payload->value['firstName']);
        self::assertSame('Doe', $payload->value['lastName']);
        self::assertEquals(new \DateTimeImmutable('1990-05-17'), $payload->value['birthday']);
        self::assertSame($this->mrSalutationId, $payload->value['salutationId']);
        self::assertArrayNotHasKey('groupId', $payload->value);
        self::assertArrayNotHasKey('addresses', $payload->value);
        self::assertArrayNotHasKey('email', $payload->value);
    }

    public function testProfileSyncNeverOverwritesWithUnmappedValues(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];

        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer(
            $provider,
            new MappedProfile('user@example.com', lastName: 'Only-Last'),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertSame(['id' => $existing->getId(), 'lastName' => 'Only-Last'], $payload->value);
    }

    public function testProfileSyncSkipsTheWriteWhenNothingChanged(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $existing->setFirstName('Jane');
        $existing->setLastName('Changed');
        $this->existingCustomers = [$existing];

        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com', firstName: 'Jane', lastName: 'Doe'), $this->identity(), $this->salesChannelContext());

        // Only the changed field; an unchanged login wouldn't write at all (R3-L29).
        self::assertSame(['id' => $existing->getId(), 'lastName' => 'Doe'], $payload->value);
    }

    public function testProfileSyncWithNothingMappedDoesNotUpdate(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $provider->setSyncCustomerAddressOnSso(true);
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];

        $this->customerRepository->expects(self::never())->method('update');

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('user@example.com'), $this->identity(), $this->salesChannelContext());
    }

    public function testProfileSyncSkipsSalutationWhenNoneResolves(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];

        $payload = $this->captureUpdatePayload();

        $this->createService(salutationsAvailable: false)->findOrCreateCustomer(
            $provider,
            new MappedProfile('user@example.com', firstName: 'Jane', salutationTechnicalName: 'mr'),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertSame(['id' => $existing->getId(), 'firstName' => 'Jane'], $payload->value);
    }

    public function testGroupSyncAppliesResolvedGroupOnly(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerGroupOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];
        $groupId = Uuid::randomHex();

        $this->groupMappingResolver->expects(self::once())
            ->method('resolveCustomerGroupId')
            ->with($provider, ['vip'], $this->context)
            ->willReturn($groupId);
        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());

        self::assertSame(['id' => $existing->getId(), 'groupId' => $groupId], $payload->value);
    }

    public function testGroupSyncLeavesGroupAloneWhenNothingResolves(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerGroupOnSso(true);
        $this->existingCustomers = [$this->customer(Uuid::randomHex(), 'user@example.com')];

        $this->groupMappingResolver->method('resolveCustomerGroupId')->willReturn(null);
        $this->customerRepository->expects(self::never())->method('update');

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());
    }

    public function testAddressSyncUpdatesExistingDefaultBillingAddressInPlace(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerAddressOnSso(true);
        $billingAddressId = Uuid::randomHex();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com', $billingAddressId);
        $this->existingCustomers = [$existing];

        $this->groupMappingResolver->expects(self::never())->method('resolveCustomerGroupId');
        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());

        // Shipping shares the billing row, so only the billing claims are
        // synced (into that one row) and no new address is created.
        self::assertSame([
            'id' => $existing->getId(),
            'addresses' => [[
                'id' => $billingAddressId,
                'street' => 'Hauptstr. 1',
                'zipcode' => '80331',
                'city' => 'Munich',
                'phoneNumber' => '+49 89 1234',
                'countryId' => $this->germanyId,
                'countryStateId' => $this->bavariaId,
            ]],
        ], $payload->value);
    }

    public function testAddressSyncUpdatesDistinctShippingAddressSeparately(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerAddressOnSso(true);
        $billingAddressId = Uuid::randomHex();
        $shippingAddressId = Uuid::randomHex();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com', $billingAddressId, $shippingAddressId);
        $this->existingCustomers = [$existing];

        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertIsArray($payload->value['addresses']);
        self::assertCount(2, $payload->value['addresses']);
        self::assertSame($billingAddressId, $payload->value['addresses'][0]['id']);
        self::assertSame([
            'id' => $shippingAddressId,
            'street' => '1 Rue de Rivoli',
            'city' => 'Paris',
            'countryId' => $this->franceId,
        ], $payload->value['addresses'][1]);
    }

    public function testAddressSyncNeverOverwritesWithUnmappedValues(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerAddressOnSso(true);
        $billingAddressId = Uuid::randomHex();
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com', $billingAddressId);
        $this->existingCustomers = [$existing];

        $payload = $this->captureUpdatePayload();

        // Unresolvable country => neither countryId nor (dependent) state synced.
        $this->createService()->findOrCreateCustomer(
            $provider,
            new MappedProfile('user@example.com', billingAddress: new AddressProfile(city: 'Berlin', state: 'Bavaria', country: 'Atlantis')),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertSame([
            'id' => $existing->getId(),
            'addresses' => [['id' => $billingAddressId, 'city' => 'Berlin']],
        ], $payload->value);
    }

    public function testAllSyncTogglesCombineIntoSingleUpdate(): void
    {
        $provider = $this->provider();
        $provider->setSyncCustomerProfileOnSso(true);
        $provider->setSyncCustomerAddressOnSso(true);
        $provider->setSyncCustomerGroupOnSso(true);
        $existing = $this->customer(Uuid::randomHex(), 'user@example.com');
        $this->existingCustomers = [$existing];
        $groupId = Uuid::randomHex();

        $this->groupMappingResolver->method('resolveCustomerGroupId')->willReturn($groupId);
        $payload = $this->captureUpdatePayload();

        $this->createService()->findOrCreateCustomer($provider, $this->fullProfile(), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertSame('Jane', $payload->value['firstName']);
        self::assertSame($groupId, $payload->value['groupId']);
        self::assertArrayHasKey('addresses', $payload->value);
    }

    public function testMissingCustomerWithAutoCreateDisabledIsDenied(): void
    {
        $provider = $this->provider();
        $provider->setAutoCreateCustomer(false);

        $this->customerRepository->expects(self::never())->method('create');
        $this->userProviderRepository->expects(self::never())->method('create');

        $this->expectException(CustomerProvisioningDeniedException::class);

        $this->createService()->findOrCreateCustomer($provider, new MappedProfile('new@example.com'), $this->identity(), $this->salesChannelContext());
    }

    public function testAutoCreateBuildsFullCustomerPayloadAndBindsProvider(): void
    {
        $provider = $this->provider();
        $groupId = Uuid::randomHex();

        $this->groupMappingResolver->expects(self::once())
            ->method('resolveCustomerGroupId')
            ->with($provider, ['vip'], $this->context)
            ->willReturn($groupId);
        $payload = $this->captureCreatePayload();

        $result = $this->createService()->findOrCreateCustomer(
            $provider,
            new MappedProfile(
                'jane@example.com',
                firstName: 'Jane',
                lastName: 'Doe',
                birthday: '1990-05-17',
                salutationTechnicalName: 'mr',
                phone: '+49 000',
                billingAddress: new AddressProfile('Hauptstr. 1', '80331', 'Munich', 'Bavaria', 'DE', '+49 89 1234'),
                groups: ['vip'],
            ),
            $this->identity(), $this->salesChannelContext(),
        );

        $customer = $payload->value;
        self::assertNotNull($customer);
        self::assertIsString($customer['id']);
        self::assertTrue(Uuid::isValid($customer['id']));
        self::assertSame($customer['id'], $result->getId());
        self::assertSame($this->salesChannelId, $customer['salesChannelId']);
        self::assertSame($this->languageId, $customer['languageId']);
        self::assertSame($groupId, $customer['groupId']);
        self::assertArrayNotHasKey('defaultPaymentMethodId', $customer, 'not a 6.7 customer field (M16)');
        self::assertSame($this->mrSalutationId, $customer['salutationId']);
        self::assertSame(self::CUSTOMER_NUMBER, $customer['customerNumber']);
        self::assertSame('Jane', $customer['firstName']);
        self::assertSame('Doe', $customer['lastName']);
        self::assertSame('jane@example.com', $customer['email']);
        self::assertFalse($customer['guest']);
        self::assertTrue($customer['active']);
        self::assertEquals(new \DateTimeImmutable('1990-05-17'), $customer['birthday']);

        self::assertIsArray($customer['addresses']);
        self::assertCount(1, $customer['addresses']);
        $address = $customer['addresses'][0];
        self::assertSame($customer['defaultBillingAddressId'], $address['id']);
        self::assertSame($customer['defaultBillingAddressId'], $customer['defaultShippingAddressId']);
        self::assertSame($customer['id'], $address['customerId']);
        self::assertSame('Jane', $address['firstName']);
        self::assertSame('Doe', $address['lastName']);
        self::assertSame('Hauptstr. 1', $address['street']);
        self::assertSame('80331', $address['zipcode']);
        self::assertSame('Munich', $address['city']);
        self::assertSame('+49 89 1234', $address['phoneNumber']);
        self::assertArrayNotHasKey('customFields', $address, 'a real address is not flagged');
        self::assertSame($this->germanyId, $address['countryId']);
        self::assertSame($this->bavariaId, $address['countryStateId']);

        self::assertCount(1, $this->bindingPayloads);
        self::assertSame($customer['id'], $this->bindingPayloads[0]['userId']);
        self::assertSame($provider->getId(), $this->bindingPayloads[0]['providerId']);
        self::assertSame(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $this->bindingPayloads[0]['userType']);
    }

    public function testJitCustomerIsGlobalUnlessTheShopBindsCustomers(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('jane@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertNull($payload->value['boundSalesChannelId'] ?? null);
        self::assertSame(Sw6OidcUserProviderEntity::GLOBAL_SCOPE, $this->bindingPayloads[0]['bindingScope']);
    }

    /**
     * R3-M13/R3-M14: core's registration rule for the bound sales channel,
     * and the binding lives in that channel's scope.
     */
    public function testJitCustomerIsBoundToTheChannelWhenTheShopBindsCustomers(): void
    {
        $this->bindCustomersToSalesChannel = true;

        $this->assertBoundToTheCurrentChannel();
    }

    /**
     * R3-M13: an unbound duplicate would make the bound account's password
     * login find the new one.
     */
    public function testJitCustomerIsBoundWhenABoundAccountWithTheEmailExists(): void
    {
        $this->boundAccountWithEmailExists = true;

        $this->assertBoundToTheCurrentChannel();
    }

    private function assertBoundToTheCurrentChannel(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('jane@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($this->salesChannelId, $payload->value['boundSalesChannelId'] ?? null);
        self::assertSame($this->salesChannelId, $this->bindingPayloads[0]['bindingScope']);
    }

    /**
     * R3-M12: two first logins at once — the loser's customer is rolled back
     * and it logs into the winner's account instead of failing.
     */
    public function testConcurrentFirstLoginUsesTheWinnersAccount(): void
    {
        $winner = $this->customer(Uuid::randomHex(), 'jane@example.com');
        $this->captureCreatePayload();
        $this->userProviderRepository = $this->createMock(EntityRepository::class);
        $this->userProviderRepository->method('create')->willReturnCallback(function () use ($winner): never {
            // The other login committed its customer and binding first.
            $this->existingCustomers = [$winner];

            throw $this->createStub(UniqueConstraintViolationException::class);
        });
        $this->userProviderRepository->method('search')->willReturnCallback(function (Criteria $criteria, Context $context) use ($winner): EntitySearchResult {
            $byUser = array_filter($criteria->getFilters(), static fn ($filter): bool => $filter instanceof EqualsFilter && $filter->getField() === 'userId') !== [];
            $entities = [];

            if ($this->existingCustomers !== [] && !$byUser) {
                $binding = new Sw6OidcUserProviderEntity();
                $binding->setId(Uuid::randomHex());
                $binding->setUserType(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER);
                $binding->setUserId($winner->getId());
                $binding->setProviderId($this->providerId);
                $entities[] = $binding;
            }

            return new EntitySearchResult(Sw6OidcUserProviderDefinition::ENTITY_NAME, \count($entities), new Sw6OidcUserProviderCollection($entities), null, $criteria, $context);
        });

        $result = $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('jane@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertSame($winner->getId(), $result->getId());
    }

    public function testCreateDispatchesBeforeAndAfterEventsAndHonorsPayloadChanges(): void
    {
        $dispatched = [];
        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addListener(CustomerBeforeCreateEvent::class, static function (CustomerBeforeCreateEvent $event) use (&$dispatched): void {
            $dispatched[] = 'before';
            $event->setPayload([...$event->getPayload(), 'customFields' => ['source' => 'oidc'], 'id' => 'ignored']);
        });
        $this->eventDispatcher->addListener(CustomerAfterCreateEvent::class, static function (CustomerAfterCreateEvent $event) use (&$dispatched): void {
            $dispatched[] = 'after:' . $event->getCustomer()->getId();
        });
        $payload = $this->captureCreatePayload();

        $result = $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('new@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertSame(['source' => 'oidc'], $payload->value['customFields']);
        self::assertSame($result->getId(), $payload->value['id'], 'the id cannot be changed by a listener');
        self::assertSame(['before', 'after:' . $result->getId()], $dispatched);
    }

    public function testAutoCreateGeneratesRandomPassword(): void
    {
        $passwords = [];

        for ($i = 0; $i < 2; ++$i) {
            $payload = $this->captureCreatePayload();
            $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('new@example.com'), $this->identity(), $this->salesChannelContext());

            self::assertNotNull($payload->value);
            self::assertIsString($payload->value['password']);
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $payload->value['password']);
            $passwords[] = $payload->value['password'];
        }

        self::assertNotSame($passwords[0], $passwords[1]);
    }

    public function testAutoCreateFallsBackToSalesChannelGroupWhenResolverReturnsNull(): void
    {
        $this->groupMappingResolver->method('resolveCustomerGroupId')->willReturn(null);
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer($this->provider(), new MappedProfile('new@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertSame($this->currentCustomerGroupId, $payload->value['groupId']);
    }

    public function testAutoCreateUsesProviderDefaultGroupViaRealResolver(): void
    {
        $defaultGroupId = Uuid::randomHex();
        $provider = $this->provider();
        $provider->setDefaultCustomerGroupId($defaultGroupId);

        $realResolver = new GroupMappingResolver($this->createStub(EntityRepository::class));
        $payload = $this->captureCreatePayload();

        $this->createService(groupMappingResolver: $realResolver)->findOrCreateCustomer($provider, new MappedProfile('new@example.com'), $this->identity(), $this->salesChannelContext());

        self::assertNotNull($payload->value);
        self::assertSame($defaultGroupId, $payload->value['groupId']);
    }

    public function testAutoCreateUsesPlaceholdersForMissingFields(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile('new@example.com', phone: '+49 000'),
            $this->identity(), $this->salesChannelContext(),
        );

        $customer = $payload->value;
        self::assertNotNull($customer);
        self::assertSame('new', $customer['firstName'], 'never the email address as a name (L9)');
        self::assertSame('-', $customer['lastName']);
        self::assertNull($customer['birthday']);
        self::assertSame($this->notSpecifiedSalutationId, $customer['salutationId']);

        self::assertIsArray($customer['addresses']);
        self::assertCount(1, $customer['addresses']);
        $address = $customer['addresses'][0];
        self::assertSame('new', $address['firstName']);
        self::assertSame('-', $address['lastName']);
        self::assertSame('-', $address['street']);
        self::assertNull($address['zipcode'], 'optional in 6.7, no placeholder');
        self::assertSame('-', $address['city']);
        self::assertSame([CustomerProvisioningService::PLACEHOLDER_ADDRESS_FIELD => true], $address['customFields']);
        self::assertSame('+49 000', $address['phoneNumber']);
        self::assertSame($this->salesChannelCountryId, $address['countryId']);
        self::assertNull($address['countryStateId']);
        self::assertSame($address['id'], $customer['defaultShippingAddressId']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidBirthdays(): iterable
    {
        yield 'not a date' => ['yesterday'];
        yield 'partial OIDC date' => ['0000-05-17'];
        yield 'before 1900' => ['1899-12-31'];
        yield 'overflowing day' => ['1990-02-31'];
        yield 'in the future' => [(new \DateTimeImmutable('+1 year'))->format('Y-m-d')];
        yield 'with time' => ['1990-05-17T10:00:00Z'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidBirthdays')]
    public function testInvalidBirthdaysAreSkippedNotFatal(string $birthday): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile('new@example.com', birthday: $birthday),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertNotNull($payload->value);
        self::assertNull($payload->value['birthday']);
    }

    public function testAutoCreateDispatchesCoresRegisterEvent(): void
    {
        $this->captureCreatePayload();
        $dispatched = [];
        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addListener(\Shopware\Core\Checkout\Customer\Event\CustomerRegisterEvent::class, static function (\Shopware\Core\Checkout\Customer\Event\CustomerRegisterEvent $event) use (&$dispatched): void {
            $dispatched[] = $event->getCustomerId();
        });

        $result = $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile('new@example.com'),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertSame([$result->getId()], $dispatched);
    }

    public function testAutoCreateFallsBackToNotSpecifiedSalutationForUnknownKey(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile('new@example.com', salutationTechnicalName: 'unknown'),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertNotNull($payload->value);
        self::assertSame($this->notSpecifiedSalutationId, $payload->value['salutationId']);
    }

    public function testAutoCreateAddsDistinctShippingAddress(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile(
                'jane@example.com',
                firstName: 'Jane',
                billingAddress: new AddressProfile('Hauptstr. 1', '80331', 'Munich', null, 'DE'),
                shippingAddress: new AddressProfile(city: 'Paris', country: 'FR', phone: '+33 1'),
            ),
            $this->identity(), $this->salesChannelContext(),
        );

        $customer = $payload->value;
        self::assertNotNull($customer);
        self::assertIsArray($customer['addresses']);
        self::assertCount(2, $customer['addresses']);
        [$billing, $shipping] = $customer['addresses'];

        self::assertSame($billing['id'], $customer['defaultBillingAddressId']);
        self::assertSame($shipping['id'], $customer['defaultShippingAddressId']);
        self::assertNotSame($billing['id'], $shipping['id']);

        self::assertSame($customer['id'], $shipping['customerId']);
        self::assertSame('Jane', $shipping['firstName']);
        self::assertSame('-', $shipping['lastName']);
        self::assertSame('-', $shipping['street']);
        self::assertNull($shipping['zipcode']);
        self::assertSame('Paris', $shipping['city']);
        self::assertSame('+33 1', $shipping['phoneNumber']);
        self::assertSame($this->franceId, $shipping['countryId']);
        self::assertNull($shipping['countryStateId']);
    }

    public function testAutoCreateIgnoresEmptyShippingAddress(): void
    {
        $payload = $this->captureCreatePayload();

        $this->createService()->findOrCreateCustomer(
            $this->provider(),
            new MappedProfile('new@example.com', shippingAddress: new AddressProfile()),
            $this->identity(), $this->salesChannelContext(),
        );

        self::assertNotNull($payload->value);
        self::assertIsArray($payload->value['addresses']);
        self::assertCount(1, $payload->value['addresses']);
        self::assertSame($payload->value['defaultBillingAddressId'], $payload->value['defaultShippingAddressId']);
    }

    private function createService(
        bool $salutationsAvailable = true,
        ?GroupMappingResolver $groupMappingResolver = null,
    ): CustomerProvisioningService {
        $bindingService = new UserProviderBindingService($this->userProviderRepository);

        return new CustomerProvisioningService(
            $this->customerRepository,
            $this->salutationRepository($salutationsAvailable),
            $this->countryResolver(),
            $groupMappingResolver ?? $this->groupMappingResolver,
            $bindingService,
            new IdentityResolver($bindingService, new NullLogger()),
            $this->numberRangeValueGenerator(),
            new NullLogger(),
            $this->eventDispatcher ??= new EventDispatcher(),
            $this->connection(),
            $this->systemConfig(),
        );
    }

    private function connection(): Connection
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('transactional')->willReturnCallback(static fn (\Closure $callback): mixed => $callback($connection));
        // No bound account with this email (core's RegisterRoute rule, R3-M13).
        $connection->method('fetchOne')->willReturnCallback(fn (): string|false => $this->boundAccountWithEmailExists ? '1' : false);

        return $connection;
    }

    private function systemConfig(): SystemConfigService
    {
        $systemConfig = $this->createStub(SystemConfigService::class);
        $systemConfig->method('get')->willReturnCallback(
            fn (string $key): bool => $key === 'core.systemWideLoginRegistration.isCustomerBoundToSalesChannel' && $this->bindCustomersToSalesChannel,
        );

        return $systemConfig;
    }

    /**
     * Linking by verified email is opted into so these tests keep exercising
     * find/create/sync; the linking policy itself is covered by
     * IdentityResolverTest and the identity tests in this class.
     */
    private function provider(): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->setId(Uuid::randomHex());
        $provider->setLinkExistingAccounts(true);
        $this->providerId = $provider->getId();

        return $provider;
    }

    /**
     * The identity of the provider most recently built by provider().
     */
    private function identity(): ExternalIdentity
    {
        return new ExternalIdentity($this->providerId, 'https://idp.example.com', $this->subject, 'user@example.com', $this->emailVerified);
    }

    private function customer(string $id, string $email, ?string $billingAddressId = null, ?string $shippingAddressId = null): CustomerEntity
    {
        $billingAddressId ??= Uuid::randomHex();

        $customer = new CustomerEntity();
        $customer->setId($id);
        $customer->setEmail($email);
        $customer->setBoundSalesChannelId(null);
        $customer->setGuest(false);
        $customer->setActive(true);
        $customer->setDefaultBillingAddressId($billingAddressId);
        $customer->setDefaultShippingAddressId($shippingAddressId ?? $billingAddressId);

        return $customer;
    }

    private function fullProfile(): MappedProfile
    {
        return new MappedProfile(
            'user@example.com',
            firstName: 'Jane',
            lastName: 'Doe',
            birthday: '1990-05-17',
            salutationTechnicalName: 'mr',
            billingAddress: new AddressProfile('Hauptstr. 1', '80331', 'Munich', 'Bavaria', 'DE', '+49 89 1234'),
            shippingAddress: new AddressProfile(street: '1 Rue de Rivoli', city: 'Paris', country: 'FR'),
            groups: ['vip'],
        );
    }

    /**
     * @param CustomerEntity[] $customers
     */
    private function customerResult(array $customers, Criteria $criteria, Context $context): EntitySearchResult
    {
        return new EntitySearchResult(
            CustomerDefinition::ENTITY_NAME,
            \count($customers),
            new CustomerCollection($customers),
            null,
            $criteria,
            $context,
        );
    }

    /**
     * @return object{value: array<string, mixed>|null}
     */
    private function captureUpdatePayload(): object
    {
        $holder = new class {
            /** @var array<string, mixed>|null */
            public ?array $value = null;
        };

        $this->customerRepository->expects(self::once())->method('update')->willReturnCallback(function (array $payloads) use ($holder) {
            self::assertCount(1, $payloads);
            $holder->value = $payloads[0];

            return EntityWrittenContainerEvent::createWithWrittenEvents([], $this->context, []);
        });

        return $holder;
    }

    /**
     * @return object{value: array<string, mixed>|null}
     */
    private function captureCreatePayload(): object
    {
        $holder = new class {
            /** @var array<string, mixed>|null */
            public ?array $value = null;
        };

        $this->customerRepository->method('create')->willReturnCallback(function (array $payloads) use ($holder) {
            self::assertCount(1, $payloads);
            $holder->value = $payloads[0];

            return EntityWrittenContainerEvent::createWithWrittenEvents([], $this->context, []);
        });

        return $holder;
    }

    private function salutationRepository(bool $available): EntityRepository
    {
        $ids = $available
            ? ['mr' => $this->mrSalutationId, 'not_specified' => $this->notSpecifiedSalutationId]
            : [];

        $repository = $this->createStub(EntityRepository::class);
        $repository->method('searchIds')->willReturnCallback(
            static function (Criteria $criteria, Context $context) use ($ids): IdSearchResult {
                $key = null;

                foreach ($criteria->getFilters() as $filter) {
                    if ($filter instanceof EqualsFilter && $filter->getField() === 'salutationKey') {
                        $key = $filter->getValue();
                    }
                }

                $found = \is_string($key) && isset($ids[$key]) ? [$ids[$key]] : [];

                return IdSearchResult::fromIds($found, $criteria, $context);
            },
        );

        return $repository;
    }

    private function countryResolver(): CountryResolver
    {
        $countries = ['DE' => $this->germanyId, 'FR' => $this->franceId];
        $states = [$this->germanyId . ':Bavaria' => $this->bavariaId];

        $resolver = $this->createStub(CountryResolver::class);
        $resolver->method('resolveCountryId')->willReturnCallback(
            static fn (?string $claim): ?string => $claim !== null ? ($countries[$claim] ?? null) : null,
        );
        $resolver->method('resolveCountryStateId')->willReturnCallback(
            static fn (?string $claim, ?string $countryId): ?string => $claim !== null && $countryId !== null
                ? ($states[$countryId . ':' . $claim] ?? null)
                : null,
        );

        return $resolver;
    }

    private function numberRangeValueGenerator(): NumberRangeValueGeneratorInterface
    {
        $generator = $this->createStub(NumberRangeValueGeneratorInterface::class);
        $generator->method('getValue')->willReturnCallback(
            fn (string $type, Context $context, ?string $salesChannelId): string => $type === 'customer' && $salesChannelId === $this->salesChannelId
                ? self::CUSTOMER_NUMBER
                : 'unexpected',
        );

        return $generator;
    }

    private function salesChannelContext(): SalesChannelContext
    {
        $customerGroup = new CustomerGroupEntity();
        $customerGroup->setId($this->currentCustomerGroupId);

        $paymentMethod = new PaymentMethodEntity();
        $paymentMethod->setId($this->paymentMethodId);

        $salesChannel = new SalesChannelEntity();
        $salesChannel->setId($this->salesChannelId);
        $salesChannel->setCountryId($this->salesChannelCountryId);

        $salesChannelContext = $this->createStub(SalesChannelContext::class);
        $salesChannelContext->method('getContext')->willReturn($this->context);
        $salesChannelContext->method('getSalesChannelId')->willReturn($this->salesChannelId);
        $salesChannelContext->method('getLanguageId')->willReturn($this->languageId);
        $salesChannelContext->method('getCurrentCustomerGroup')->willReturn($customerGroup);
        $salesChannelContext->method('getPaymentMethod')->willReturn($paymentMethod);
        $salesChannelContext->method('getSalesChannel')->willReturn($salesChannel);

        return $salesChannelContext;
    }
}
