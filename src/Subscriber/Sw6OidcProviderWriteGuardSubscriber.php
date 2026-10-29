<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\IssuerChangeConfirmationStore;
use MartinKuhl\Sw6Oidc\Service\Security\LockoutConfirmationStore;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\Message\PasswordSessionRevocationMessage;
use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Save-time validation for every DAL write to sw6oidc_provider (Admin UI, API,
 * CLI import alike):
 *
 *  - SSRF: every URL the plugin will fetch server-side must pass
 *    SsrfUrlValidator (https, public address). `issuer` is only ever compared,
 *    never fetched, so it isn't checked. Outbound calls are additionally
 *    guarded at request time (Sw6OidcHttpClientFactory), since DNS can change
 *    after save.
 *  - The health-alert webhook URL is fetched too, so it is SSRF-checked as
 *    well; it is encrypted by the time this event runs, so it is decrypted
 *    here first.
 *  - Redirect URLs the browser is sent to (post_logout_url) must be absolute
 *    http(s) URLs — never fetched server-side, so no SSRF check, but no
 *    javascript:/data: or relative values either.
 *  - Client secret: required for confidential clients (R3-M23); changing a
 *    URL the secret is sent to, or turning a public client confidential,
 *    requires entering it again in the same save (N-M12, R3-M4). Decided on
 *    the *stored* `public_client`, so a two-step save can't skip it.
 *  - SSO-only mode (R3-H7): the result of the write is checked, whatever
 *    field changed (flag, `is_active`, `login_type`, delete) — see
 *    SsoOnlyInvariant. It must leave an active admin able to log in through
 *    SSO, an SSO button visible, and when it turns Administration password
 *    login on for admins without a binding, an explicit confirmation by the
 *    acting admin (LockoutConfirmationStore; CLI counts as confirmed).
 *    Customer password login can only be turned off once this provider has
 *    a bound customer. The break-glass SW6OIDC_ALLOW_PASSWORD_LOGIN=1
 *    always remains.
 *  - When the effective policy goes from off to on, sessions that were
 *    started with a password by accounts without any SSO binding are ended,
 *    after commit and from the message queue.
 *  - Issuer change (R3-M9): bindings belong to an issuer, so after the
 *    change they no longer match. A provider with bound accounts needs the
 *    acting superadmin's decision (IssuerChangeConfirmationStore): re-bind
 *    them to the new issuer after commit (same IdP, new URL), or leave them
 *    disconnected (another tenant). CLI writes leave them disconnected.
 *
 * Who may change trust-relevant fields is checked separately
 * (ProviderTrustGuardSubscriber).
 *
 * Violations are reported against the camelCase property path, so the admin
 * form can show them on the right field.
 */
class Sw6OidcProviderWriteGuardSubscriber implements EventSubscriberInterface, ResetInterface
{
    public const CODE_URL_BLOCKED = 'SW6OIDC_URL_BLOCKED';
    public const CODE_LOCKOUT_GUARD = 'SW6OIDC_LOCKOUT_GUARD';
    public const CODE_REDIRECT_URL_INVALID = 'SW6OIDC_REDIRECT_URL_INVALID';
    public const CODE_LOCKOUT_UNBOUND_USERS = 'SW6OIDC_LOCKOUT_UNBOUND_USERS';
    public const CODE_NO_VISIBLE_LOGIN = 'SW6OIDC_NO_VISIBLE_LOGIN';
    public const CODE_SECRET_REQUIRED = 'SW6OIDC_SECRET_REQUIRED_FOR_ENDPOINT_CHANGE';
    public const CODE_CLIENT_SECRET_REQUIRED = 'SW6OIDC_CLIENT_SECRET_REQUIRED';
    public const CODE_ISSUER_CHANGE_CONFIRM = 'SW6OIDC_ISSUER_CHANGE_CONFIRM';
    public const CODE_VALUE_REQUIRED = 'SW6OIDC_VALUE_REQUIRED';
    public const CODE_PROVIDER_HAS_BINDINGS = 'SW6OIDC_PROVIDER_HAS_BINDINGS';

    /**
     * Context state of a provider delete the admin confirmed although it
     * disconnects accounts (OidcProviderAdminController::deleteWithBindings).
     */
    public const STATE_BINDING_LOSS_CONFIRMED = 'sw6oidc.provider_binding_loss_confirmed';

    /** NOT NULL boolean columns: an explicit null is a 400, not a database 500 (R3-L43). */
    private const NOT_NULL_BOOLEANS = [
        'public_client' => 'publicClient',
        'auto_create_customer' => 'autoCreateCustomer',
        'auto_create_admin' => 'autoCreateAdmin',
        'disable_non_oidc_admin_login' => 'disableNonOidcAdminLogin',
        'disable_non_oidc_customer_login' => 'disableNonOidcCustomerLogin',
        'show_customer_link' => 'showCustomerLink',
        'show_admin_link' => 'showAdminLink',
        'is_active' => 'isActive',
        'sync_customer_profile_on_sso' => 'syncCustomerProfileOnSso',
        'sync_customer_address_on_sso' => 'syncCustomerAddressOnSso',
        'sync_customer_group_on_sso' => 'syncCustomerGroupOnSso',
        'sync_admin_profile_on_sso' => 'syncAdminProfileOnSso',
        'sync_admin_role_on_sso' => 'syncAdminRoleOnSso',
        'allow_superadmin_group_mapping' => 'allowSuperadminGroupMapping',
        'require_email_verified' => 'requireEmailVerified',
        'link_existing_accounts' => 'linkExistingAccounts',
        'frontchannel_admin_logout' => 'frontchannelAdminLogout',
        'revoke_superadmin_on_sso' => 'revokeSuperadminOnSso',
        'health_alert_notify_on_recovery' => 'healthAlertNotifyOnRecovery',
    ];

    /**
     * URLs the client secret (or tokens) are sent to: changing one on an
     * existing confidential provider requires re-entering the secret in the
     * same save, like browsers do for saved passwords — otherwise anyone
     * with provider:update could redirect the "write-only" secret to their
     * own host on the next login (N-M12). storage name => property name
     */
    private const CREDENTIAL_URL_FIELDS = [
        'access_token_endpoint' => 'accessTokenEndpoint',
        'revocation_endpoint' => 'revocationEndpoint',
        'user_info_endpoint' => 'userInfoEndpoint',
        'well_known_config_url' => 'wellKnownConfigUrl',
    ];

    /** Columns that decide the SSO-only policy, with their database defaults for inserts. */
    private const POLICY_COLUMNS = [
        'is_active' => 1,
        'login_type' => 'both',
        'disable_non_oidc_admin_login' => 0,
        'disable_non_oidc_customer_login' => 0,
        'show_admin_link' => 1,
        'show_customer_link' => 1,
        // Bindings only count for the provider's current issuer (R3-M9).
        'issuer' => null,
    ];

    /** login type => [flag column, flag property] */
    private const LOCKOUT_FLAGS = [
        LoginType::Admin->value => ['disable_non_oidc_admin_login', 'disableNonOidcAdminLogin'],
        LoginType::Customer->value => ['disable_non_oidc_customer_login', 'disableNonOidcCustomerLogin'],
    ];

    /** storage name => property name */
    private const REDIRECT_URL_FIELDS = [
        'post_logout_url' => 'postLogoutUrl',
    ];

    /** storage name => property name */
    private const FETCHED_URL_FIELDS = [
        'well_known_config_url' => 'wellKnownConfigUrl',
        'authorize_endpoint' => 'authorizeEndpoint',
        'access_token_endpoint' => 'accessTokenEndpoint',
        'user_info_endpoint' => 'userInfoEndpoint',
        'jwks_endpoint' => 'jwksEndpoint',
        'end_session_endpoint' => 'endSessionEndpoint',
        'revocation_endpoint' => 'revocationEndpoint',
    ];

    /** Encrypted fetched URLs: storage name => property name */
    private const ENCRYPTED_FETCHED_URL_FIELDS = [
        'health_alert_webhook_url' => 'healthAlertWebhookUrl',
    ];

    /** @var array<string, true> user types whose password login a pending write turns off */
    private array $pendingRevocations = [];

    /** @var array<string, true> provider ids (hex) of that pending write */
    private array $pendingProviderIds = [];

    /** @var array<string, string> provider id (hex) => new issuer its bindings move to after commit */
    private array $pendingRebinds = [];

    public function __construct(
        private readonly SsrfUrlValidator $urlValidator,
        private readonly Connection $connection,
        private readonly Sw6OidcEncryptor $encryptor,
        private readonly SsoOnlyInvariant $invariant,
        private readonly MessageBusInterface $messageBus,
        private readonly RequestStack $requestStack,
        private readonly LockoutConfirmationStore $confirmationStore,
        private readonly LoggerInterface $logger,
        private readonly IssuerChangeConfirmationStore $issuerChangeConfirmations,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            PreWriteValidationEvent::class => 'validate',
            Sw6OidcProviderDefinition::ENTITY_NAME . '.written' => 'onProviderWritten',
            Sw6OidcProviderDefinition::ENTITY_NAME . '.deleted' => 'onProviderWritten',
        ];
    }

    public function reset(): void
    {
        $this->pendingRevocations = [];
        $this->pendingProviderIds = [];
        $this->pendingRebinds = [];
    }

    public function validate(PreWriteValidationEvent $event): void
    {
        $commands = $event->getCommandsForEntity(Sw6OidcProviderDefinition::ENTITY_NAME);

        if ($commands === []) {
            return;
        }

        // A previous write that failed after validation must not leave its revocation behind.
        $this->reset();

        /** @var array<string, array<string, mixed>|null> $changes provider id => policy columns after the write, null = deleted */
        $changes = [];
        /** @var array<string, WriteCommand> $commandsById */
        $commandsById = [];
        /** @var array<string, ConstraintViolationList> $violations */
        $violations = [];
        /** @var list<string> $rebinding providers whose bindings move to the new issuer with this write */
        $rebinding = [];

        foreach ($commands as $command) {
            $idBytes = $command->getPrimaryKey()['id'] ?? null;

            if (!\is_string($idBytes)) {
                continue;
            }

            $id = Uuid::fromBytesToHex($idBytes);
            $commandsById[$id] = $command;
            $violations[$id] = new ConstraintViolationList();

            if ($command instanceof DeleteCommand) {
                $changes[$id] = null;
                $this->validateDeleteKeepsBindings($idBytes, $violations[$id], $event->getContext());

                continue;
            }

            if (!$command instanceof InsertCommand && !$command instanceof UpdateCommand) {
                continue;
            }

            $current = $command instanceof UpdateCommand ? $this->currentRow($idBytes) : null;

            $this->validateNotNull($command, $violations[$id]);
            $this->validateUrls($command, $violations[$id]);
            $this->validateRedirectUrls($command, $violations[$id]);
            $this->validateClientSecret($command, $current, $violations[$id]);
            $this->validateCustomerLockout($command, $idBytes, $current, $violations[$id]);
            $this->validateEmailVerification($command, $idBytes, $current, $violations[$id]);

            if ($this->validateIssuerChange($command, $id, $current, $violations[$id], $event->getContext()) === IssuerChangeConfirmationStore::DECISION_REBIND) {
                $rebinding[] = $id;
            }

            $changes[$id] = $this->policyColumnsAfter($command, $current);
        }

        $this->validateSsoOnlyMode($changes, $commandsById, $violations, $event->getContext(), $rebinding);

        foreach ($violations as $id => $list) {
            if ($list->count() > 0) {
                $event->getExceptions()->add(new WriteConstraintViolationException($list, $commandsById[$id]->getPath()));
            }
        }
    }

    /**
     * Ends password-started sessions of unbound accounts once the write that
     * turned password login off has actually been committed.
     */
    public function onProviderWritten(EntityWrittenEvent $event): void
    {
        $this->applyRebinds($event);

        if ($this->pendingRevocations === []) {
            return;
        }

        $written = array_filter($event->getIds(), fn (mixed $id): bool => \is_string($id) && isset($this->pendingProviderIds[strtolower($id)]));

        if ($written === []) {
            return;
        }

        foreach (array_keys($this->pendingRevocations) as $userType) {
            $this->messageBus->dispatch(new PasswordSessionRevocationMessage($userType));
        }

        $this->reset();
    }

    private function validateUrls(WriteCommand $command, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        $urls = [];

        foreach (self::FETCHED_URL_FIELDS as $storageName => $propertyName) {
            $urls[$propertyName] = $payload[$storageName] ?? null;
        }

        foreach (self::ENCRYPTED_FETCHED_URL_FIELDS as $storageName => $propertyName) {
            $value = $payload[$storageName] ?? null;
            $urls[$propertyName] = \is_string($value) ? $this->encryptor->decrypt($value, 'sw6oidc_provider.' . $storageName) : null;
        }

        foreach ($urls as $propertyName => $url) {
            if (!\is_string($url) || $url === '') {
                continue;
            }

            $result = $this->urlValidator->validate($url);

            if ($result['blocked']) {
                $violations->add($this->violation(implode(' ', $result['warnings']), $propertyName, $url, self::CODE_URL_BLOCKED));
            }
        }
    }

    private function validateRedirectUrls(WriteCommand $command, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        foreach (self::REDIRECT_URL_FIELDS as $storageName => $propertyName) {
            $url = $payload[$storageName] ?? null;

            if (!\is_string($url) || $url === '') {
                continue;
            }

            $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
            $host = parse_url($url, PHP_URL_HOST);

            if (!\in_array($scheme, ['https', 'http'], true) || !\is_string($host) || $host === '') {
                $violations->add($this->violation('Must be an absolute http(s) URL.', $propertyName, $url, self::CODE_REDIRECT_URL_INVALID));
            }
        }
    }

    /**
     * @param array<string, mixed>|null $current the stored row (update) or null (insert)
     */
    private function validateClientSecret(WriteCommand $command, ?array $current, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();
        $secretEntered = \is_string($payload['client_secret'] ?? null) && $payload['client_secret'] !== '';

        if ($secretEntered) {
            return;
        }

        $storedPublic = (bool) ($current['public_client'] ?? false);
        $publicAfter = \array_key_exists('public_client', $payload) ? (bool) $payload['public_client'] : $storedPublic;
        $storedSecret = (string) ($current['client_secret'] ?? '');

        if (!$publicAfter && ($current === null || $storedSecret === '' || $storedPublic)) {
            // A new confidential client, one without a stored secret, or a
            // public client turned confidential: the secret must be entered
            // now, never inherited from an earlier public-client save (R3-M4).
            $violations->add($this->violation('A confidential client needs its client secret.', 'clientSecret', null, self::CODE_CLIENT_SECRET_REQUIRED));

            return;
        }

        if ($current === null || $storedPublic || $storedSecret === '') {
            return;
        }

        $changed = [];

        foreach (self::CREDENTIAL_URL_FIELDS as $storageName => $propertyName) {
            if (\array_key_exists($storageName, $payload) && (string) $payload[$storageName] !== (string) ($current[$storageName] ?? '')) {
                $changed[] = $propertyName;
            }
        }

        // One violation on the secret field, which is what the admin has to fill in.
        if ($changed !== []) {
            $violations->add($this->violation(
                'Enter the client secret again: it will be sent to the changed URL(s) ' . implode(', ', $changed) . '.',
                'clientSecret',
                $changed,
                self::CODE_SECRET_REQUIRED,
            ));
        }
    }

    /**
     * Customer password login can only be switched off once at least one
     * customer is bound to this provider — otherwise nobody could log in.
     *
     * @param array<string, mixed>|null $current
     */
    private function validateCustomerLockout(WriteCommand $command, string $providerIdBytes, ?array $current, ConstraintViolationList $violations): void
    {
        [$column, $property] = self::LOCKOUT_FLAGS['customer'];
        $payload = $command->getPayload();

        if (!(bool) ($payload[$column] ?? false) || (bool) ($current[$column] ?? false)) {
            return;
        }

        $hasBoundCustomer = $this->connection->fetchOne(
            'SELECT 1 FROM `sw6oidc_user_provider` WHERE `provider_id` = :providerId AND `user_type` = :userType LIMIT 1',
            ['providerId' => $providerIdBytes, 'userType' => Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER],
            ['providerId' => ParameterType::BINARY],
        ) !== false;

        if (!$hasBoundCustomer) {
            $violations->add($this->violation(
                'Password login for customer accounts can only be disabled once at least one customer account has signed in through this provider — otherwise nobody could log in.',
                $property,
                true,
                self::CODE_LOCKOUT_GUARD,
            ));
        }
    }

    /**
     * Requiring a verified email while the email is mapped from another
     * claim or transformed would refuse every login (R3-M15; the other
     * direction is checked by AttributeMappingWriteGuardSubscriber).
     *
     * @param array<string, mixed>|null $current
     */
    private function validateEmailVerification(WriteCommand $command, string $providerIdBytes, ?array $current, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        if ($current === null || !(bool) ($payload['require_email_verified'] ?? false) || (bool) ($current['require_email_verified'] ?? false)) {
            return;
        }

        $mappings = $this->connection->fetchAllAssociative(
            'SELECT `attribute_name`, `transform_function` FROM `sw6oidc_attribute_mapping` WHERE `provider_id` = :id AND `attribute_type` = :type',
            ['id' => $providerIdBytes, 'type' => Sw6OidcAttributeMappingDefinition::TYPE_EMAIL],
            ['id' => ParameterType::BINARY],
        );

        foreach ($mappings as $mapping) {
            if (!AttributeMappingWriteGuardSubscriber::isVerifiableEmailMapping($mapping['attribute_name'], $mapping['transform_function'])) {
                $violations->add($this->violation(
                    'A verified email can only be required while the email is mapped from the "email" claim without a transform.',
                    'requireEmailVerified',
                    true,
                    AttributeMappingWriteGuardSubscriber::CODE_EMAIL_UNVERIFIABLE,
                ));

                return;
            }
        }
    }

    /**
     * @param array<string, mixed>|null $current
     *
     * @return IssuerChangeConfirmationStore::DECISION_*|null the decision, when the issuer changes with bound accounts
     */
    private function validateIssuerChange(WriteCommand $command, string $providerId, ?array $current, ConstraintViolationList $violations, Context $context): ?string
    {
        $payload = $command->getPayload();

        if ($current === null || !\array_key_exists('issuer', $payload)) {
            return null;
        }

        $newIssuer = trim((string) $payload['issuer']);

        if ($newIssuer === trim((string) ($current['issuer'] ?? ''))) {
            return null;
        }

        $affected = (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM `sw6oidc_user_provider` WHERE `provider_id` = :id AND (`issuer_hash` IS NULL OR `issuer_hash` <> :hash)',
            ['id' => Uuid::fromHexToBytes($providerId), 'hash' => UserProviderBindingService::issuerHash($newIssuer)],
            ['id' => ParameterType::BINARY],
        );

        if ($affected === 0) {
            return null;
        }

        $decision = $this->issuerChangeDecision($providerId, $context);

        if ($decision === null) {
            $violations->add($this->violation(
                \sprintf(
                    '%d account(s) are connected to the previous issuer. Decide whether they stay connected '
                    . '(the same identity provider under a new URL) or are disconnected (another identity provider).',
                    $affected,
                ),
                'issuer',
                $newIssuer,
                self::CODE_ISSUER_CHANGE_CONFIRM,
            ));

            return null;
        }

        if ($decision === IssuerChangeConfirmationStore::DECISION_REBIND && $newIssuer !== '') {
            $this->pendingRebinds[$providerId] = $newIssuer;
        }

        $outcome = $decision === IssuerChangeConfirmationStore::DECISION_REBIND ? 're-bound to the new issuer.' : 'disconnected.';
        $this->logger->warning('sw6oidc: provider issuer changes; connected accounts are ' . $outcome, [
            'providerId' => $providerId,
            'accounts' => $affected,
        ]);

        return $decision;
    }

    /**
     * @return IssuerChangeConfirmationStore::DECISION_*|null
     */
    private function issuerChangeDecision(string $providerId, Context $context): ?string
    {
        // CLI (config import): never moves accounts to another issuer implicitly.
        if (!$this->requestStack->getMainRequest() instanceof Request) {
            return IssuerChangeConfirmationStore::DECISION_DISCONNECT;
        }

        $source = $context->getSource();
        $userId = $source instanceof AdminApiSource ? $source->getUserId() : null;

        return $userId !== null ? $this->issuerChangeConfirmations->consume($providerId, $userId) : null;
    }

    private function applyRebinds(EntityWrittenEvent $event): void
    {
        foreach ($event->getIds() as $id) {
            if (!\is_string($id) || !isset($this->pendingRebinds[strtolower($id)])) {
                continue;
            }

            $issuer = $this->pendingRebinds[strtolower($id)];
            unset($this->pendingRebinds[strtolower($id)]);

            try {
                $this->connection->executeStatement(
                    'UPDATE `sw6oidc_user_provider` SET `issuer` = :issuer, `issuer_hash` = :hash WHERE `provider_id` = :id',
                    ['issuer' => $issuer, 'hash' => UserProviderBindingService::issuerHash($issuer), 'id' => Uuid::fromHexToBytes($id)],
                    ['id' => ParameterType::BINARY],
                );
            } catch (\Throwable $exception) {
                $this->logger->error('sw6oidc: re-binding the accounts of a provider to its new issuer failed.', [
                    'providerId' => $id,
                    'exception' => $exception->getMessage(),
                ]);
            }
        }
    }

    /**
     * Checks the SSO-only policy *after* all provider changes of this write
     * against the state before it (R3-H7). A write is refused only when it
     * makes things worse, so an already inconsistent state can be repaired.
     *
     * @param array<string, array<string, mixed>|null> $changes
     * @param array<string, WriteCommand>              $commandsById
     * @param array<string, ConstraintViolationList>   $violations
     * @param list<string>                             $rebinding providers whose bindings move to the new issuer
     */
    private function validateSsoOnlyMode(array $changes, array $commandsById, array $violations, Context $context, array $rebinding = []): void
    {
        if ($changes === []) {
            return;
        }

        foreach (self::LOCKOUT_FLAGS as $userType => [, $property]) {
            if (!$this->invariant->passwordLoginDisabled($userType, $changes)) {
                continue;
            }

            $disabledBefore = $this->invariant->passwordLoginDisabled($userType);
            $affected = $this->affectedCommands($changes, $commandsById);

            if (!$this->invariant->loginButtonVisible($userType, $changes) && (!$disabledBefore || $this->invariant->loginButtonVisible($userType))) {
                $this->addToAll($violations, $affected, $this->violation(
                    'Password login can only be disabled while the login page shows at least one SSO button for these accounts.',
                    $property,
                    true,
                    self::CODE_NO_VISIBLE_LOGIN,
                ));

                continue;
            }

            if ($userType === LoginType::Admin->value) {
                if (!$this->invariant->adminAccessPossible($changes, rebindProviderIds: $rebinding) && $this->invariant->holds()) {
                    $this->addToAll($violations, $affected, $this->violation(
                        'Administration password login is disabled and no active admin could log in through an active provider after this change.',
                        $property,
                        true,
                        self::CODE_LOCKOUT_GUARD,
                    ));

                    continue;
                }

                if (!$disabledBefore) {
                    $unbound = \count($this->invariant->unboundActiveAdminIds($changes));

                    if ($unbound > 0 && !$this->lockoutConfirmed(array_keys($affected), $context)) {
                        $this->addToAll($violations, $affected, $this->violation(
                            \sprintf(
                                '%d active admin account(s) have no single sign-on binding and would be locked out. Confirm to disable password login anyway.',
                                $unbound,
                            ),
                            $property,
                            true,
                            self::CODE_LOCKOUT_UNBOUND_USERS,
                        ));

                        continue;
                    }
                }
            }

            if (!$disabledBefore) {
                $this->pendingRevocations[$userType] = true;

                foreach (array_keys($changes) as $id) {
                    $this->pendingProviderIds[$id] = true;
                }
            }
        }
    }

    /**
     * The commands that touch the policy columns (or delete a provider):
     * the violation belongs to them.
     *
     * @param array<string, array<string, mixed>|null> $changes
     * @param array<string, WriteCommand>              $commandsById
     *
     * @return array<string, WriteCommand>
     */
    private function affectedCommands(array $changes, array $commandsById): array
    {
        $affected = array_filter(
            $commandsById,
            static fn (WriteCommand $command): bool => $command instanceof DeleteCommand
                || array_intersect_key($command->getPayload(), self::POLICY_COLUMNS) !== [],
        );

        // Fall back to every command, so a violation is never lost.
        return $affected !== [] ? $affected : array_intersect_key($commandsById, $changes);
    }

    /**
     * @param array<string, ConstraintViolationList> $violations
     * @param array<string, WriteCommand>            $affected
     */
    private function addToAll(array $violations, array $affected, ConstraintViolation $violation): void
    {
        foreach (array_keys($affected) as $id) {
            $violations[$id]->add($violation);
        }
    }

    /**
     * @param array<string, mixed>|null $current
     *
     * @return array<string, mixed>
     */
    private function policyColumnsAfter(WriteCommand $command, ?array $current): array
    {
        $columns = [];
        $payload = $command->getPayload();

        foreach (self::POLICY_COLUMNS as $column => $default) {
            $columns[$column] = \array_key_exists($column, $payload) ? $payload[$column] : ($current[$column] ?? $default);
        }

        return $columns;
    }

    /**
     * @param list<string> $providerIds
     */
    private function lockoutConfirmed(array $providerIds, Context $context): bool
    {
        // CLI (config import) runs without a request: the operator is explicit.
        if (!$this->requestStack->getMainRequest() instanceof Request) {
            return true;
        }

        $source = $context->getSource();
        $userId = $source instanceof AdminApiSource ? $source->getUserId() : null;

        if ($userId === null) {
            return false;
        }

        foreach ($providerIds as $providerId) {
            if ($this->confirmationStore->consume($providerId, $userId)) {
                $this->logger->warning('sw6oidc: Administration password login disabled despite admins without SSO binding (confirmed).', [
                    'providerId' => $providerId,
                    'adminUserId' => $userId,
                ]);

                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function currentRow(string $providerIdBytes): ?array
    {
        $row = $this->connection->fetchAssociative(
            'SELECT `is_active`, `login_type`, `disable_non_oidc_admin_login`, `disable_non_oidc_customer_login`, `show_admin_link`, `show_customer_link`,
                    `public_client`, `client_secret`, `access_token_endpoint`, `revocation_endpoint`, `user_info_endpoint`, `well_known_config_url`,
                    `require_email_verified`, `issuer`
             FROM `sw6oidc_provider` WHERE `id` = :id',
            ['id' => $providerIdBytes],
            ['id' => ParameterType::BINARY],
        );

        return $row === false ? null : $row;
    }

    private function validateNotNull(WriteCommand $command, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        foreach (self::NOT_NULL_BOOLEANS as $storageName => $propertyName) {
            if (\array_key_exists($storageName, $payload) && $payload[$storageName] === null) {
                $violations->add($this->violation('This value must be true or false.', $propertyName, null, self::CODE_VALUE_REQUIRED));
            }
        }
    }

    /**
     * Deleting a provider deletes its account bindings with it (database
     * cascade): those accounts can't use SSO any more. A plain API delete is
     * refused while bindings exist; the Administration asks and then deletes
     * through the confirming endpoint (R3-L43). CLI/system writes are trusted.
     */
    private function validateDeleteKeepsBindings(string $idBytes, ConstraintViolationList $violations, Context $context): void
    {
        if ($context->hasState(self::STATE_BINDING_LOSS_CONFIRMED) || !$context->getSource() instanceof AdminApiSource) {
            return;
        }

        $bindings = (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM `sw6oidc_user_provider` WHERE `provider_id` = :id',
            ['id' => $idBytes],
            ['id' => ParameterType::BINARY],
        );

        if ($bindings > 0) {
            $violations->add($this->violation(
                sprintf('Deleting this provider disconnects %d account(s) from single sign-on. Confirm the deletion to continue.', $bindings),
                'id',
                $bindings,
                self::CODE_PROVIDER_HAS_BINDINGS,
            ));
        }
    }

    private function violation(string $message, string $propertyName, mixed $invalidValue, string $code): ConstraintViolation
    {
        return new ConstraintViolation($message, $message, [], null, '/' . $propertyName, $invalidValue, null, $code);
    }
}
