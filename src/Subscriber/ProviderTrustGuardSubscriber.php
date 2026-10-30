<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Field\AssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StorageAware;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * Who may change what a provider trusts (R3-H4). Whoever controls the
 * endpoints, the issuer, the scope or the superadmin mapping of a provider
 * can log in as any account bound to it, superadmins included; the role and
 * password-login flags decide who keeps superadmin and who can log in at
 * all. So the `sw6oidc_provider` editor role may change only the fields on
 * an allow-list (EDITOR_FIELDS); every other column needs a superadmin (or
 * an admin integration), the CLI or system scope. Deny by default (R8-H1): a
 * new column is protected until someone puts it on the list. Covered:
 *
 * - every provider column not in EDITOR_FIELDS, on insert and update;
 * - role mapping rows that grant Administration roles or superadmin;
 * - email/username attribute mappings and access-control rules of providers
 *   that serve Administration logins.
 *
 * Every trust-field change is logged at warning level with the acting
 * admin, whoever makes it (audit trail).
 */
class ProviderTrustGuardSubscriber implements EventSubscriberInterface
{
    public const CODE_SUPERADMIN_REQUIRED = 'SW6OIDC_SUPERADMIN_REQUIRED';

    /**
     * Provider columns the editor role may change: presentation, customer
     * provisioning, operations, the secret (re-entry only — the URLs it is
     * sent to are protected), and the live test's bookkeeping.
     * storage name => property name
     */
    public const EDITOR_FIELDS = [
        'app_name' => 'appName',
        'display_name' => 'displayName',
        'is_active' => 'isActive',
        'sort_order' => 'sortOrder',
        'show_customer_link' => 'showCustomerLink',
        'show_admin_link' => 'showAdminLink',
        'client_secret' => 'clientSecret',
        'post_logout_url' => 'postLogoutUrl',
        'auto_create_customer' => 'autoCreateCustomer',
        'default_customer_group_id' => 'defaultCustomerGroupId',
        'disable_non_oidc_customer_login' => 'disableNonOidcCustomerLogin',
        'sync_customer_profile_on_sso' => 'syncCustomerProfileOnSso',
        'sync_customer_address_on_sso' => 'syncCustomerAddressOnSso',
        'sync_customer_group_on_sso' => 'syncCustomerGroupOnSso',
        'http_timeout' => 'httpTimeout',
        'jwks_cache_ttl' => 'jwksCacheTtl',
        'health_alert_webhook_url' => 'healthAlertWebhookUrl',
        'health_alert_failure_threshold' => 'healthAlertFailureThreshold',
        'health_alert_notify_on_recovery' => 'healthAlertNotifyOnRecovery',
        'last_test_status' => 'lastTestStatus',
        'last_test_at' => 'lastTestAt',
        'last_test_claims' => 'lastTestClaims',
    ];

    /** Bookkeeping the DAL writes itself. */
    private const IGNORED_COLUMNS = ['id', 'created_at', 'updated_at'];

    private const ADMIN_MAPPING_TYPES = [
        Sw6OidcRoleMappingDefinition::MAPPING_TYPE_ADMIN_ROLE,
        Sw6OidcRoleMappingDefinition::MAPPING_TYPE_SUPERADMIN,
    ];

    /** Attribute types that decide which account a login resolves to. */
    private const IDENTITY_ATTRIBUTE_TYPES = [
        Sw6OidcAttributeMappingDefinition::TYPE_EMAIL,
        Sw6OidcAttributeMappingDefinition::TYPE_USERNAME,
    ];

    private const JSON_FIELDS = ['base64_claims'];

    /** @var array<string, string>|null storage name => property name */
    private ?array $trustFields = null;

    public function __construct(
        private readonly Connection $connection,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcProviderDefinition $providerDefinition,
    ) {
    }

    /**
     * Every writable provider column that isn't on the editor allow-list.
     *
     * @return array<string, string> storage name => property name
     */
    public function trustFields(): array
    {
        if ($this->trustFields !== null) {
            return $this->trustFields;
        }

        $fields = [];

        foreach ($this->providerDefinition->getFields() as $field) {
            if (
                !$field instanceof StorageAware
                || $field instanceof AssociationField
                || $field->is(WriteProtected::class)
                || \in_array($field->getStorageName(), self::IGNORED_COLUMNS, true)
                || \array_key_exists($field->getStorageName(), self::EDITOR_FIELDS)
            ) {
                continue;
            }

            $fields[$field->getStorageName()] = $field->getPropertyName();
        }

        return $this->trustFields = $fields;
    }

    public static function getSubscribedEvents(): array
    {
        return [PreWriteValidationEvent::class => 'validate'];
    }

    public function validate(PreWriteValidationEvent $event): void
    {
        $context = $event->getContext();
        $privileged = $this->isPrivileged($context);
        /** @var array<string, string> $loginTypes provider id (hex) => login type after this write */
        $loginTypes = [];

        foreach ($event->getCommandsForEntity(Sw6OidcProviderDefinition::ENTITY_NAME) as $command) {
            if (!$command instanceof InsertCommand && !$command instanceof UpdateCommand) {
                continue;
            }

            $providerId = $this->hexId($command);
            $current = $command instanceof UpdateCommand ? $this->currentProviderRow($command) : null;
            $loginType = $command->getPayload()['login_type'] ?? $current['login_type'] ?? 'both';
            $loginTypes[$providerId] = \is_string($loginType) ? $loginType : 'both';

            $changed = $this->changedTrustFields($command, $current);

            if ($changed === []) {
                continue;
            }

            $this->audit($providerId, $changed, $command, $context);

            if (!$privileged) {
                $this->refuse($event, $command, array_values($changed));
            }
        }

        if ($privileged) {
            return;
        }

        foreach ($event->getCommandsForEntity(Sw6OidcRoleMappingDefinition::ENTITY_NAME) as $command) {
            $stored = $command instanceof InsertCommand ? null : $this->storedChildRow('sw6oidc_role_mapping', $command, 'mapping_type');
            $types = [$command->getPayload()['mapping_type'] ?? null, $stored['mapping_type'] ?? null];

            if (array_intersect($types, self::ADMIN_MAPPING_TYPES) !== []) {
                $this->refuse($event, $command, ['mappingType']);
            }
        }

        foreach ($event->getCommandsForEntity(Sw6OidcAttributeMappingDefinition::ENTITY_NAME) as $command) {
            $stored = $command instanceof InsertCommand ? null : $this->storedChildRow('sw6oidc_attribute_mapping', $command, 'attribute_type');
            $types = [$command->getPayload()['attribute_type'] ?? null, $stored['attribute_type'] ?? null];

            if (array_intersect($types, self::IDENTITY_ATTRIBUTE_TYPES) !== [] && $this->servesAdmins($command, $stored, $loginTypes)) {
                $this->refuse($event, $command, ['attributeType']);
            }
        }

        foreach ($event->getCommandsForEntity(Sw6OidcAccessControlRuleDefinition::ENTITY_NAME) as $command) {
            $stored = $command instanceof InsertCommand ? null : $this->storedChildRow('sw6oidc_access_control_rule', $command);

            if ($this->servesAdmins($command, $stored, $loginTypes)) {
                $this->refuse($event, $command, ['claimKey']);
            }
        }
    }

    /**
     * Superadmins and admin integrations; system scope (CLI, the plugin's
     * own writes) and anything that isn't an Admin API caller.
     */
    private function isPrivileged(Context $context): bool
    {
        if ($context->getScope() === Context::SYSTEM_SCOPE) {
            return true;
        }

        $source = $context->getSource();

        return !$source instanceof AdminApiSource || $source->isAdmin();
    }

    /**
     * @param array<string, mixed>|null $current
     *
     * @return array<string, string> storage name => property name
     */
    private function changedTrustFields(WriteCommand $command, ?array $current): array
    {
        $payload = $command->getPayload();
        $changed = [];

        foreach ($this->trustFields() as $storageName => $propertyName) {
            if (!\array_key_exists($storageName, $payload)) {
                continue;
            }

            if ($current === null || $this->normalize($storageName, $payload[$storageName]) !== $this->normalize($storageName, $current[$storageName] ?? null)) {
                $changed[$storageName] = $propertyName;
            }
        }

        return $changed;
    }

    private function normalize(string $storageName, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (\in_array($storageName, self::JSON_FIELDS, true) && \is_string($value)) {
            return json_encode(json_decode($value, true)) ?: $value;
        }

        return \is_scalar($value) ? (string) $value : (json_encode($value) ?: null);
    }

    /**
     * @param array<string, string> $changed
     */
    private function audit(string $providerId, array $changed, WriteCommand $command, Context $context): void
    {
        $payload = $command->getPayload();
        $values = [];

        foreach (array_keys($changed) as $storageName) {
            $value = $payload[$storageName];
            $values[$changed[$storageName]] = \is_string($value) && !mb_check_encoding($value, 'UTF-8') ? Uuid::fromBytesToHex($value) : $value;
        }

        $source = $context->getSource();
        $this->logger->warning('sw6oidc: trust-relevant provider settings changed.', [
            'providerId' => $providerId,
            'operation' => $command instanceof InsertCommand ? 'insert' : 'update',
            'changes' => $values,
            'adminUserId' => $source instanceof AdminApiSource ? $source->getUserId() : null,
            'integrationId' => $source instanceof AdminApiSource ? $source->getIntegrationId() : null,
        ]);
    }

    /**
     * @param array<string, mixed>|null $stored
     * @param array<string, string>     $loginTypes
     */
    private function servesAdmins(WriteCommand $command, ?array $stored, array $loginTypes): bool
    {
        $providerId = $command->getPayload()['provider_id'] ?? $stored['provider_id'] ?? null;

        if (!\is_string($providerId)) {
            // Unknown provider: fail safe.
            return true;
        }

        $hexId = Uuid::fromBytesToHex($providerId);
        $loginType = $loginTypes[$hexId] ?? $this->connection->fetchOne(
            'SELECT `login_type` FROM `sw6oidc_provider` WHERE `id` = :id',
            ['id' => $providerId],
            ['id' => ParameterType::BINARY],
        );

        return !\is_string($loginType) || $loginType !== 'customer';
    }

    /**
     * @param list<string> $propertyNames
     */
    private function refuse(PreWriteValidationEvent $event, WriteCommand $command, array $propertyNames): void
    {
        $message = 'Only a superadmin can change the security-relevant settings of a single sign-on provider.';
        $violations = new ConstraintViolationList();

        foreach ($propertyNames as $propertyName) {
            $violations->add(new ConstraintViolation($message, $message, [], null, '/' . $propertyName, null, null, self::CODE_SUPERADMIN_REQUIRED));
        }

        $event->getExceptions()->add(new WriteConstraintViolationException($violations, $command->getPath()));
    }

    /**
     * @return array<string, mixed>|null
     */
    private function currentProviderRow(WriteCommand $command): ?array
    {
        $row = $this->connection->fetchAssociative(
            \sprintf('SELECT `%s` FROM `sw6oidc_provider` WHERE `id` = :id', implode('`, `', array_keys($this->trustFields()))),
            ['id' => $command->getPrimaryKey()['id'] ?? null],
            ['id' => ParameterType::BINARY],
        );

        return $row === false ? null : $row;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function storedChildRow(string $table, WriteCommand $command, ?string $column = null): ?array
    {
        $row = $this->connection->fetchAssociative(
            \sprintf('SELECT `provider_id`%s FROM `%s` WHERE `id` = :id', $column !== null ? ', `' . $column . '`' : '', $table),
            ['id' => $command->getPrimaryKey()['id'] ?? null],
            ['id' => ParameterType::BINARY],
        );

        return $row === false ? null : $row;
    }

    private function hexId(WriteCommand $command): string
    {
        $id = $command->getPrimaryKey()['id'] ?? null;

        return \is_string($id) ? Uuid::fromBytesToHex($id) : '';
    }
}
