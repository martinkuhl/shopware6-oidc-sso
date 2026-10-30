<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber\ProviderValidation;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use MartinKuhl\Sw6Oidc\Subscriber\AttributeMappingWriteGuardSubscriber;
use MartinKuhl\Sw6Oidc\Subscriber\Sw6OidcProviderWriteGuardSubscriber;
use Shopware\Core\Framework\DataAbstractionLayer\Field\BoolField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\IntField;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * The checks of a provider write that look at that one provider row only:
 * not-null values, URLs (SSRF), redirect URLs, the client secret and the
 * email-verification setting. Stateless; the SSO-only invariant, lockout
 * confirmations, issuer changes and post-commit side effects stay in
 * Sw6OidcProviderWriteGuardSubscriber, which runs these first (R8-M-2).
 */
class ProviderFieldValidator
{
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

    public function __construct(
        private readonly SsrfUrlValidator $urlValidator,
        private readonly Sw6OidcEncryptor $encryptor,
        private readonly Connection $connection,
        private readonly Sw6OidcProviderDefinition $providerDefinition,
    ) {
    }

    /**
     * An explicit null for a Required bool or int field is a 400, not a
     * database 500 (R3-L43): core's serializers validate Required strings
     * (NotBlank) but let null through for bools and ints. Derived from the
     * definition, so a new NOT NULL field is covered once it is Required.
     */
    public function validateNotNull(WriteCommand $command, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        foreach ($this->providerDefinition->getFields() as $field) {
            if (
                ($field instanceof BoolField || $field instanceof IntField)
                && $field->is(Required::class)
                && \array_key_exists($field->getStorageName(), $payload)
                && $payload[$field->getStorageName()] === null
            ) {
                $violations->add($this->violation('This value is required.', $field->getPropertyName(), null, Sw6OidcProviderWriteGuardSubscriber::CODE_VALUE_REQUIRED));
            }
        }
    }
    public function validateUrls(WriteCommand $command, ConstraintViolationList $violations): void
    {
        $payload = $command->getPayload();

        $urls = [];

        foreach (self::FETCHED_URL_FIELDS as $storageName => $propertyName) {
            $urls[$propertyName] = $payload[$storageName] ?? null;
        }

        foreach (self::ENCRYPTED_FETCHED_URL_FIELDS as $storageName => $propertyName) {
            $value = $payload[$storageName] ?? null;
            $urls[$propertyName] = \is_string($value) ? $this->encryptor->decrypt($value, Sw6OidcProviderDefinition::encryptionPurpose($storageName)) : null;
        }

        foreach ($urls as $propertyName => $url) {
            if (!\is_string($url) || $url === '') {
                continue;
            }

            $result = $this->urlValidator->validate($url);

            if ($result['blocked']) {
                $violations->add($this->violation(implode(' ', $result['warnings']), $propertyName, $url, Sw6OidcProviderWriteGuardSubscriber::CODE_URL_BLOCKED));
            }
        }
    }
    public function validateRedirectUrls(WriteCommand $command, ConstraintViolationList $violations): void
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
                $violations->add($this->violation('Must be an absolute http(s) URL.', $propertyName, $url, Sw6OidcProviderWriteGuardSubscriber::CODE_REDIRECT_URL_INVALID));
            }
        }
    }
    /**
     * @param array<string, mixed>|null $current the stored row (update) or null (insert)
     */
    public function validateClientSecret(WriteCommand $command, ?array $current, ConstraintViolationList $violations): void
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
            $violations->add($this->violation(
                'A confidential client needs its client secret.',
                'clientSecret',
                null,
                Sw6OidcProviderWriteGuardSubscriber::CODE_CLIENT_SECRET_REQUIRED,
            ));

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
                Sw6OidcProviderWriteGuardSubscriber::CODE_SECRET_REQUIRED,
            ));
        }
    }
    /**
     * Requiring a verified email while the email is mapped from another
     * claim or transformed would refuse every login (R3-M15; the other
     * direction is checked by AttributeMappingWriteGuardSubscriber).
     *
     * @param array<string, mixed>|null $current
     * @param list<WriteCommand>        $mappingCommands
     */
    public function validateEmailVerification(WriteCommand $command, string $providerIdBytes, ?array $current, ConstraintViolationList $violations, array $mappingCommands): void
    {
        $payload = $command->getPayload();

        if ($current === null || !(bool) ($payload['require_email_verified'] ?? false) || (bool) ($current['require_email_verified'] ?? false)) {
            return;
        }

        $mappings = array_filter(
            $this->mappingsAfterWrite($providerIdBytes, $mappingCommands),
            static fn (array $mapping): bool => ($mapping['attribute_type'] ?? null) === Sw6OidcAttributeMappingDefinition::TYPE_EMAIL,
        );

        foreach ($mappings as $mapping) {
            if (!AttributeMappingWriteGuardSubscriber::isVerifiableEmailMapping($mapping['attribute_name'] ?? null, $mapping['transform_function'] ?? null)) {
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
     * The provider's attribute mappings as this write leaves them: the stored
     * rows with the mapping commands of the same save applied (insert,
     * update, delete), so changing the email mapping and requiring a
     * verified email in one save is judged on the result (R8-L22).
     *
     * @param list<WriteCommand> $mappingCommands
     *
     * @return array<string, array{attribute_type?: mixed, attribute_name?: mixed, transform_function?: mixed}> by binary id
     */
    private function mappingsAfterWrite(string $providerIdBytes, array $mappingCommands): array
    {
        $rows = [];
        $stored = $this->connection->fetchAllAssociative(
            'SELECT `id`, `attribute_type`, `attribute_name`, `transform_function` FROM `sw6oidc_attribute_mapping` WHERE `provider_id` = :id',
            ['id' => $providerIdBytes],
            ['id' => ParameterType::BINARY],
        );

        foreach ($stored as $row) {
            $rows[(string) $row['id']] = $row;
        }

        foreach ($mappingCommands as $command) {
            $id = $command->getPrimaryKey()['id'] ?? null;

            if (!\is_string($id)) {
                continue;
            }

            if ($command instanceof DeleteCommand) {
                unset($rows[$id]);

                continue;
            }

            $payload = $command->getPayload();

            if ($command instanceof InsertCommand ? ($payload['provider_id'] ?? null) !== $providerIdBytes : !isset($rows[$id])) {
                continue;
            }

            $rows[$id] = array_intersect_key($payload, array_flip(['attribute_type', 'attribute_name', 'transform_function'])) + ($rows[$id] ?? []);
        }

        return $rows;
    }

    private function violation(string $message, string $propertyName, mixed $invalidValue, string $code): ConstraintViolation
    {
        return new ConstraintViolation($message, $message, [], null, '/' . $propertyName, $invalidValue, null, $code);
    }
}
