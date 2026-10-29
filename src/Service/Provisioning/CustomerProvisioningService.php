<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Event\CustomerAfterCreateEvent;
use MartinKuhl\Sw6Oidc\Event\CustomerBeforeCreateEvent;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\CustomerProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\CustomerCollection;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\Event\CustomerRegisterEvent;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\NumberRange\ValueGenerator\NumberRangeValueGeneratorInterface;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\Salutation\SalutationCollection;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Finds-or-JIT-creates a Shopware customer from a MappedProfile, enforcing
 * per-user IdP binding and resolving group mapping. The create payload
 * follows the Shopware 6.7 DAL contract for customer + customer_address and
 * is exercised by the integration suite (StorefrontOidcLoginTest).
 */
class CustomerProvisioningService
{
    /**
     * customer_address.customFields flag: the address was created from
     * placeholders because the IdP sent no address claims. Shopware 6.7
     * requires default addresses (street, city); the customer completes it
     * at checkout or in the account, and address sync replaces it once the
     * IdP sends one (M16).
     */
    public const PLACEHOLDER_ADDRESS_FIELD = 'sw6oidc_placeholder_address';

    private const PLACEHOLDER = '-';

    private const MIN_BIRTH_YEAR = 1900;

    /**
     * @param EntityRepository<CustomerCollection> $customerRepository
     * @param EntityRepository<SalutationCollection> $salutationRepository
     */
    public function __construct(
        private readonly EntityRepository $customerRepository,
        private readonly EntityRepository $salutationRepository,
        private readonly CountryResolver $countryResolver,
        private readonly GroupMappingResolver $groupMappingResolver,
        private readonly UserProviderBindingService $bindingService,
        private readonly IdentityResolver $identityResolver,
        private readonly NumberRangeValueGeneratorInterface $numberRangeValueGenerator,
        private readonly LoggerInterface $logger,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly Connection $connection,
        private readonly SystemConfigService $systemConfigService,
    ) {
    }

    /**
     * @throws CustomerProvisioningDeniedException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException
     */
    public function findOrCreateCustomer(
        Sw6OidcProviderEntity $provider,
        MappedProfile $profile,
        ExternalIdentity $identity,
        SalesChannelContext $salesChannelContext,
    ): CustomerEntity {
        $context = $salesChannelContext->getContext();
        $salesChannelId = $salesChannelContext->getSalesChannelId();
        $emailMatch = $this->findByEmail($profile->email, $salesChannelContext);

        $customerId = $this->identityResolver->resolve(
            Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER,
            $provider,
            $identity,
            $emailMatch?->getId(),
            false,
            $context,
            $salesChannelId,
            // A channel-bound customer is bound in its channel's scope (R3-M14).
            $emailMatch?->getBoundSalesChannelId(),
        );

        if ($customerId !== null) {
            $existing = $this->existingCustomer($customerId, $emailMatch, $salesChannelContext);
            $this->syncExisting($provider, $existing, $profile, $salesChannelContext);

            return $existing;
        }

        if (!$provider->isAutoCreateCustomer()) {
            throw new CustomerProvisioningDeniedException('No customer account exists for this identity and auto-creation is disabled for this provider.');
        }

        // Shopware's own registration rule for the bound sales channel (R3-M13).
        $boundSalesChannelId = $this->boundSalesChannelId($profile->email, $salesChannelId);

        try {
            // Create and bind together: a concurrent first login of the same
            // subject must not leave an unbound duplicate behind (R3-M12).
            $customerId = $this->connection->transactional(function () use ($provider, $profile, $salesChannelContext, $boundSalesChannelId, $identity, $context): string {
                $customerId = $this->create($provider, $profile, $salesChannelContext, $boundSalesChannelId);
                $this->bindingService->bind(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $customerId, $identity, $context, $boundSalesChannelId);

                return $customerId;
            });
        } catch (UniqueConstraintViolationException | SubjectAlreadyLinkedException | ProviderMismatchException $exception) {
            $winnerId = $this->bindingService->findUserIdBySubject(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $identity, $context, $salesChannelId);

            if ($winnerId === null) {
                throw $exception;
            }

            $this->logger->info('sw6oidc: concurrent first login; using the account the other login created.', [
                'providerId' => $provider->getId(),
                'customerId' => $winnerId,
            ]);

            return $this->existingCustomer($winnerId, null, $salesChannelContext);
        }

        $created = $this->customerRepository->search(new Criteria([$customerId]), $context)->first();
        \assert($created instanceof CustomerEntity);

        $this->eventDispatcher->dispatch(new CustomerAfterCreateEvent($provider, $profile, $created, $salesChannelContext));

        // Core's registration event, so Flow Builder flows (welcome mail,
        // tagging, ...) run for SSO-created customers too (M16).
        $this->eventDispatcher->dispatch(new CustomerRegisterEvent($salesChannelContext, $created));

        return $created;
    }

    /**
     * @throws CustomerProvisioningDeniedException when the account can't log in to this sales channel
     */
    private function existingCustomer(string $customerId, ?CustomerEntity $emailMatch, SalesChannelContext $salesChannelContext): CustomerEntity
    {
        $existing = $emailMatch instanceof CustomerEntity && $emailMatch->getId() === $customerId
            ? $emailMatch
            : $this->customerRepository->search(new Criteria([$customerId]), $salesChannelContext->getContext())->first();

        if (
            !$existing instanceof CustomerEntity
            || $existing->getGuest()
            || !CustomerSalesChannelBinding::allows($existing, $salesChannelContext->getSalesChannelId())
        ) {
            throw new CustomerProvisioningDeniedException('The customer bound to this identity is not available in this sales channel.');
        }

        return $existing;
    }

    /**
     * Core's RegisterRoute rule: a new customer is bound to the sales channel
     * when the shop binds customers to sales channels, or when a bound
     * account with this email already exists — otherwise that account's
     * password login would start finding the new, unbound duplicate (R3-M13).
     */
    private function boundSalesChannelId(string $email, string $salesChannelId): ?string
    {
        if ($this->systemConfigService->get('core.systemWideLoginRegistration.isCustomerBoundToSalesChannel')) {
            return $salesChannelId;
        }

        $hasBoundAccount = $this->connection->fetchOne(
            'SELECT 1 FROM `customer` WHERE `email` = :email AND `bound_sales_channel_id` IS NOT NULL LIMIT 1',
            ['email' => $email],
        ) !== false;

        return $hasBoundAccount ? $salesChannelId : null;
    }

    private function findByEmail(string $email, SalesChannelContext $salesChannelContext): ?CustomerEntity
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('email', $email));
        $criteria->addFilter(new EqualsFilter('guest', false));
        // Newest first, like core's AccountService (R3-L26).
        $criteria->addSorting(new FieldSorting('createdAt', FieldSorting::DESCENDING));

        $inactiveMatch = null;

        foreach ($this->customerRepository->search($criteria, $salesChannelContext->getContext())->getEntities() as $customer) {
            if (!CustomerSalesChannelBinding::allows($customer, $salesChannelContext->getSalesChannelId())) {
                continue;
            }

            if ($customer->getActive()) {
                return $customer;
            }

            $inactiveMatch ??= $customer;
        }

        // An inactive account is still returned, never skipped: otherwise SSO
        // would create a fresh account for a customer the shop deactivated.
        return $inactiveMatch;
    }

    private function create(Sw6OidcProviderEntity $provider, MappedProfile $profile, SalesChannelContext $salesChannelContext, ?string $boundSalesChannelId): string
    {
        $context = $salesChannelContext->getContext();
        $customerId = Uuid::randomHex();
        $billingAddressId = Uuid::randomHex();

        $groupId = $this->groupMappingResolver->resolveCustomerGroupId($provider, $profile->groups, $context)
            ?? $salesChannelContext->getCurrentCustomerGroup()->getId();

        $customerNumber = $this->numberRangeValueGenerator->getValue(
            'customer',
            $context,
            $salesChannelContext->getSalesChannelId(),
        );

        $billing = $profile->billingAddress;

        $billingCountryId = $this->countryResolver->resolveCountryId($billing?->country, $context)
            ?? $salesChannelContext->getSalesChannel()->getCountryId();

        // $billing is genuinely nullable (no billing address claim mapped) -
        // PHPStan's nullsafe.neverNull flags each `?->` below as
        // "unnecessary" even in a minimal repro where $billing is narrowed
        // to non-null immediately beforehand, so this looks like a rule
        // quirk rather than a real finding; following its suggested fix
        // (plain ->) would throw on a null $billing instead of falling
        // through to the '-' default.
        $firstName = $this->fallbackFirstName($profile);
        $lastName = $profile->lastName ?? self::PLACEHOLDER;

        $addressPayload = [
            'id' => $billingAddressId,
            'customerId' => $customerId,
            'firstName' => $firstName,
            'lastName' => $lastName,
            'street' => $billing?->street ?? self::PLACEHOLDER, // @phpstan-ignore nullsafe.neverNull
            'zipcode' => $billing?->zipcode,
            'city' => $billing?->city ?? self::PLACEHOLDER, // @phpstan-ignore nullsafe.neverNull
            'phoneNumber' => $billing?->phone ?? $profile->phone, // @phpstan-ignore nullsafe.neverNull
            'countryId' => $billingCountryId,
            'countryStateId' => $this->countryResolver->resolveCountryStateId($billing?->state, $billingCountryId, $context),
        ];

        if ($billing?->street === null || $billing->city === null) {
            $addressPayload['customFields'] = [self::PLACEHOLDER_ADDRESS_FIELD => true];
        }

        $customerPayload = [
            'id' => $customerId,
            'salesChannelId' => $salesChannelContext->getSalesChannelId(),
            'languageId' => $salesChannelContext->getLanguageId(),
            'groupId' => $groupId,
            'salutationId' => $this->resolveSalutationId($profile->salutationTechnicalName, $context),
            'customerNumber' => $customerNumber,
            'firstName' => $firstName,
            'lastName' => $lastName,
            'email' => $profile->email,
            'boundSalesChannelId' => $boundSalesChannelId,
            'guest' => false,
            'active' => true,
            'password' => bin2hex(random_bytes(32)),
            'birthday' => $this->parseBirthday($profile->birthday),
            'addresses' => [$addressPayload],
            'defaultBillingAddressId' => $billingAddressId,
            'defaultShippingAddressId' => $billingAddressId,
        ];

        if ($profile->shippingAddress instanceof \MartinKuhl\Sw6Oidc\Service\Provisioning\AddressProfile && !$profile->shippingAddress->isEmpty()) {
            $shippingAddressId = Uuid::randomHex();
            $shipping = $profile->shippingAddress;

            $shippingCountryId = $this->countryResolver->resolveCountryId($shipping->country, $context)
                ?? $salesChannelContext->getSalesChannel()->getCountryId();

            $customerPayload['addresses'][] = [
                'id' => $shippingAddressId,
                'customerId' => $customerId,
                'firstName' => $firstName,
                'lastName' => $lastName,
                'street' => $shipping->street ?? self::PLACEHOLDER,
                'zipcode' => $shipping->zipcode,
                'city' => $shipping->city ?? self::PLACEHOLDER,
                'phoneNumber' => $shipping->phone,
                'countryId' => $shippingCountryId,
                'countryStateId' => $this->countryResolver->resolveCountryStateId($shipping->state, $shippingCountryId, $context),
            ];
            $customerPayload['defaultShippingAddressId'] = $shippingAddressId;
        }

        $event = new CustomerBeforeCreateEvent($provider, $profile, $customerPayload, $salesChannelContext);
        $this->eventDispatcher->dispatch($event);
        $customerPayload = [...$event->getPayload(), 'id' => $customerId];

        $this->customerRepository->create([$customerPayload], $context);

        $this->logger->info('sw6oidc: JIT-created customer via OIDC.', [
            'providerId' => $provider->getId(),
            'customerId' => $customerId,
        ]);

        return $customerId;
    }

    /**
     * Re-applies mapped claims to an already-existing (bound) customer on
     * every login, per the provider's independent sync_* toggles. Each is
     * additive/partial-update only: a claim that isn't mapped (null on the
     * profile) or a group mapping that doesn't resolve is simply left
     * alone, never overwritten with a placeholder — this is a refresh of
     * whatever the IdP actually provided, not a reset to defaults. Address
     * sync only ever updates the customer's *existing* default billing/
     * shipping addresses in place (never creates one here) — this method
     * never grows to be a rerun of the full create() path, which is unaware
     * of the pre-existing customer_address invariants (customerId, all
     * Shopware-required fields) an update to a currently-nonexistent id
     * would need. Shipping is skipped entirely when it's the same address
     * row as billing (create() only ever splits them into two rows when a
     * distinct shipping address was actually mapped) — syncing it a second
     * time from separate shipping-claim data would otherwise overwrite that
     * one shared row with two different, possibly conflicting sets of
     * values in the same update call.
     */
    private function syncExisting(
        Sw6OidcProviderEntity $provider,
        CustomerEntity $existing,
        MappedProfile $profile,
        SalesChannelContext $salesChannelContext,
    ): void {
        $context = $salesChannelContext->getContext();
        $payload = ['id' => $existing->getId()];

        if ($provider->isSyncCustomerProfileOnSso()) {
            if ($profile->firstName !== null) {
                $payload['firstName'] = $profile->firstName;
            }

            if ($profile->lastName !== null) {
                $payload['lastName'] = $profile->lastName;
            }

            $birthday = $this->parseBirthday($profile->birthday);

            if ($birthday instanceof \DateTimeImmutable) {
                $payload['birthday'] = $birthday;
            }

            if ($profile->salutationTechnicalName !== null) {
                $salutationId = $this->resolveSalutationId($profile->salutationTechnicalName, $context);

                if ($salutationId !== null) {
                    $payload['salutationId'] = $salutationId;
                }
            }
        }

        if ($provider->isSyncCustomerGroupOnSso()) {
            // Only a matching mapping changes the group; the provider default
            // is for new accounts and must not undo a merchant's choice (R3-M11).
            $groupId = $this->groupMappingResolver->resolveCustomerGroupId($provider, $profile->groups, $context, withDefault: false);

            if ($groupId !== null) {
                $payload['groupId'] = $groupId;
            }
        }

        if ($provider->isSyncCustomerAddressOnSso()) {
            $addressPayloads = [];

            $billingAddressId = $existing->getDefaultBillingAddressId();
            $billingPayload = $this->buildAddressSyncPayload($billingAddressId, $profile->billingAddress, $context);

            if ($billingPayload !== null) {
                $addressPayloads[] = $billingPayload;
            }

            $shippingAddressId = $existing->getDefaultShippingAddressId();

            if ($shippingAddressId !== $billingAddressId) {
                $shippingPayload = $this->buildAddressSyncPayload($shippingAddressId, $profile->shippingAddress, $context);

                if ($shippingPayload !== null) {
                    $addressPayloads[] = $shippingPayload;
                }
            }

            $addressPayloads = $this->withoutUnchangedAddressFields($addressPayloads);

            if ($addressPayloads !== []) {
                $payload['addresses'] = $addressPayloads;
            }
        }

        // Most logins change nothing: no write, so no *.written events,
        // indexers or subscribers run for it (R3-L29).
        $payload = $this->withoutUnchanged($payload, $existing->getVars());

        if (\count($payload) > 1) {
            $this->customerRepository->update([$payload], $context);
        }
    }

    /**
     * Drops the fields of a write payload that already hold that value.
     *
     * @param array<string, mixed> $payload `id` plus fields
     * @param array<string, mixed> $current field => stored value (missing = unknown, kept)
     *
     * @return array<string, mixed>
     */
    private function withoutUnchanged(array $payload, array $current): array
    {
        foreach ($payload as $field => $value) {
            if ($field === 'id' || !\array_key_exists($field, $current)) {
                continue;
            }

            $stored = $current[$field];
            $same = match (true) {
                // Birthdays: a date, whatever the time part.
                $value instanceof \DateTimeInterface, $stored instanceof \DateTimeInterface => $this->dateOf($value) === $this->dateOf($stored),
                // Ids: hex in any case.
                str_ends_with($field, 'Id') => \is_string($value) && \is_string($stored) && strtolower($value) === strtolower($stored),
                default => $value === $stored,
            };

            if ($same) {
                unset($payload[$field]);
            }
        }

        return $payload;
    }

    private function dateOf(mixed $value): mixed
    {
        return $value instanceof \DateTimeInterface ? $value->format('Y-m-d') : $value;
    }

    /**
     * @param list<array<string, mixed>> $addressPayloads
     *
     * @return list<array<string, mixed>> only addresses with a changed field
     */
    private function withoutUnchangedAddressFields(array $addressPayloads): array
    {
        if ($addressPayloads === []) {
            return [];
        }

        $rows = $this->connection->fetchAllAssociative(
            'SELECT LOWER(HEX(`id`)) AS `id`, `street`, `zipcode`, `city`, `phone_number` AS `phoneNumber`,
                    LOWER(HEX(`country_id`)) AS `countryId`, LOWER(HEX(`country_state_id`)) AS `countryStateId`
             FROM `customer_address` WHERE `id` IN (:ids)',
            ['ids' => array_map(static fn (array $address): string => Uuid::fromHexToBytes((string) $address['id']), $addressPayloads)],
            ['ids' => ArrayParameterType::BINARY],
        );
        $current = array_column($rows, null, 'id');

        $changed = [];

        foreach ($addressPayloads as $address) {
            $address = $this->withoutUnchanged($address, $current[strtolower((string) $address['id'])] ?? []);

            if (\count($address) > 1) {
                $changed[] = $address;
            }
        }

        return $changed;
    }

    /**
     * @return array<string, mixed>|null null if there's nothing mapped to sync
     */
    private function buildAddressSyncPayload(string $addressId, ?AddressProfile $address, Context $context): ?array
    {
        if (!$address instanceof AddressProfile || $address->isEmpty()) {
            return null;
        }

        $addressPayload = ['id' => $addressId];

        if ($address->street !== null) {
            $addressPayload['street'] = $address->street;
        }

        if ($address->zipcode !== null) {
            $addressPayload['zipcode'] = $address->zipcode;
        }

        if ($address->city !== null) {
            $addressPayload['city'] = $address->city;
        }

        if ($address->phone !== null) {
            $addressPayload['phoneNumber'] = $address->phone;
        }

        $countryId = $this->countryResolver->resolveCountryId($address->country, $context);

        if ($countryId !== null) {
            $addressPayload['countryId'] = $countryId;
        }

        // State can only be resolved once its country is known - if the
        // country claim isn't mapped/didn't resolve this login, the state
        // claim (if any) is simply left unsynced rather than guessed against
        // whatever country the address currently happens to have.
        if ($countryId !== null && $address->state !== null) {
            $countryStateId = $this->countryResolver->resolveCountryStateId($address->state, $countryId, $context);

            if ($countryStateId !== null) {
                $addressPayload['countryStateId'] = $countryStateId;
            }
        }

        return \count($addressPayload) > 1 ? $addressPayload : null;
    }

    /**
     * Never the email address as a name (L9): it would end up on invoices
     * and in mails. The local part is a readable, editable stand-in.
     */
    private function fallbackFirstName(MappedProfile $profile): string
    {
        if ($profile->firstName !== null) {
            return $profile->firstName;
        }

        $localPart = trim(explode('@', $profile->email)[0]);

        return $localPart !== '' ? mb_substr($localPart, 0, 255) : self::PLACEHOLDER;
    }

    /**
     * Strict Y-m-d (OIDC `birthdate`), between 1900 and today. Anything else
     * — including partial dates like "0000-05-17" — is logged and skipped
     * instead of failing the login or storing nonsense (M9).
     */
    private function parseBirthday(?string $value): ?\DateTimeImmutable
    {
        if ($value === null || trim($value) === '') {
            return null;
        }

        $date = \DateTimeImmutable::createFromFormat('!Y-m-d', trim($value));
        $errors = \DateTimeImmutable::getLastErrors();

        if (
            !$date instanceof \DateTimeImmutable
            || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
            || (int) $date->format('Y') < self::MIN_BIRTH_YEAR
            || $date > new \DateTimeImmutable('today')
        ) {
            $this->logger->notice('sw6oidc: ignoring an invalid birthdate claim.');

            return null;
        }

        return $date;
    }

    private function resolveSalutationId(?string $technicalName, Context $context): ?string
    {
        $criteria = new Criteria();
        $criteria->setLimit(1);
        $criteria->addFilter(new EqualsFilter('salutationKey', $technicalName ?? 'not_specified'));

        $id = $this->salutationRepository->searchIds($criteria, $context)->firstId();

        if ($id !== null) {
            return $id;
        }

        $fallbackCriteria = new Criteria();
        $fallbackCriteria->setLimit(1);
        $fallbackCriteria->addFilter(new EqualsFilter('salutationKey', 'not_specified'));

        return $this->salutationRepository->searchIds($fallbackCriteria, $context)->firstId();
    }
}
