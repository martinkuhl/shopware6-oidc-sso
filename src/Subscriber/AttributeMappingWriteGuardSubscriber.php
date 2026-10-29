<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeTransformer;
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
 * Attribute mappings that can't work are refused when they are saved, not
 * at every login. Updates are judged on the stored row merged with the
 * change, since an update only carries the changed columns (R3-M24).
 *
 * - A regex_replace transform needs a valid pattern (F-N16); for email and
 *   username an invalid one would fail every login (N-L7).
 * - While the provider requires a verified email (`require_email_verified`),
 *   the email must be the standard `email` claim, untransformed: the IdP
 *   only vouches for that one, so anything else makes every login fail
 *   with "email not verified" — bound accounts included (R3-M15).
 *   Switching `require_email_verified` on is checked the other way round in
 *   Sw6OidcProviderWriteGuardSubscriber.
 */
class AttributeMappingWriteGuardSubscriber implements EventSubscriberInterface
{
    public const CODE_INVALID_PATTERN = 'SW6OIDC_TRANSFORM_PATTERN_INVALID';
    public const CODE_EMAIL_UNVERIFIABLE = 'SW6OIDC_EMAIL_TRANSFORM_UNVERIFIABLE';

    private const COLUMNS = ['provider_id', 'attribute_type', 'attribute_name', 'transform_function', 'transform_params'];

    public function __construct(private readonly Connection $connection)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [PreWriteValidationEvent::class => 'validate'];
    }

    public function validate(PreWriteValidationEvent $event): void
    {
        $requireVerified = $this->requireEmailVerifiedInEvent($event);

        foreach ($event->getCommandsForEntity(Sw6OidcAttributeMappingDefinition::ENTITY_NAME) as $command) {
            if (!$command instanceof InsertCommand && !$command instanceof UpdateCommand) {
                continue;
            }

            $mapping = $this->merged($command);
            $violations = new ConstraintViolationList();

            if ($mapping['transform_function'] === AttributeTransformer::REGEX_REPLACE) {
                $params = \is_string($mapping['transform_params']) ? json_decode($mapping['transform_params'], true) : $mapping['transform_params'];
                $pattern = \is_array($params) ? ($params['pattern'] ?? null) : null;

                if (!self::isValidPattern($pattern)) {
                    $message = 'The regular expression is invalid (use delimiters, e.g. /^(.*)@example\.com$/).';
                    $violations->add(new ConstraintViolation($message, $message, [], null, '/transformParams/pattern', $pattern, null, self::CODE_INVALID_PATTERN));
                }
            }

            if (
                $mapping['attribute_type'] === Sw6OidcAttributeMappingDefinition::TYPE_EMAIL
                && !self::isVerifiableEmailMapping($mapping['attribute_name'], $mapping['transform_function'])
                && $this->requiresVerifiedEmail($mapping['provider_id'], $requireVerified)
            ) {
                $message = 'While the provider requires a verified email, the email must be mapped from the "email" claim without a transform: '
                    . 'the identity provider only verifies that one.';
                $violations->add(new ConstraintViolation($message, $message, [], null, '/transformFunction', $mapping['transform_function'], null, self::CODE_EMAIL_UNVERIFIABLE));
            }

            if ($violations->count() > 0) {
                $event->getExceptions()->add(new WriteConstraintViolationException($violations, $command->getPath()));
            }
        }
    }

    public static function isValidPattern(mixed $pattern): bool
    {
        if (!\is_string($pattern) || $pattern === '' || \strlen($pattern) > AttributeTransformer::MAX_REGEX_BYTES) {
            return false;
        }

        // A compile error makes preg_match() return false (and warn).
        return @preg_match($pattern, '') !== false;
    }

    /**
     * Whether the IdP's `email_verified` can vouch for an email mapped like this.
     */
    public static function isVerifiableEmailMapping(mixed $attributeName, mixed $transformFunction): bool
    {
        return ($transformFunction === null || $transformFunction === '')
            && \is_string($attributeName) && strtolower(trim($attributeName)) === 'email';
    }

    /**
     * @return array<string, mixed> the mapping's columns after this write
     */
    private function merged(WriteCommand $command): array
    {
        $stored = [];

        if ($command instanceof UpdateCommand) {
            $row = $this->connection->fetchAssociative(
                \sprintf('SELECT `%s` FROM `sw6oidc_attribute_mapping` WHERE `id` = :id', implode('`, `', self::COLUMNS)),
                ['id' => $command->getPrimaryKey()['id'] ?? null],
                ['id' => ParameterType::BINARY],
            );
            $stored = \is_array($row) ? $row : [];
        }

        $merged = [];

        foreach (self::COLUMNS as $column) {
            $merged[$column] = \array_key_exists($column, $command->getPayload()) ? $command->getPayload()[$column] : ($stored[$column] ?? null);
        }

        return $merged;
    }

    /**
     * `require_email_verified` of providers written in the same event.
     *
     * @return array<string, bool> provider id (hex) => value after the write
     */
    private function requireEmailVerifiedInEvent(PreWriteValidationEvent $event): array
    {
        $values = [];

        foreach ($event->getCommandsForEntity(Sw6OidcProviderDefinition::ENTITY_NAME) as $command) {
            $id = $command->getPrimaryKey()['id'] ?? null;

            if (\is_string($id) && \array_key_exists('require_email_verified', $command->getPayload())) {
                $values[Uuid::fromBytesToHex($id)] = (bool) $command->getPayload()['require_email_verified'];
            } elseif (\is_string($id) && $command instanceof InsertCommand) {
                // The database default.
                $values[Uuid::fromBytesToHex($id)] = true;
            }
        }

        return $values;
    }

    /**
     * @param array<string, bool> $inEvent
     */
    private function requiresVerifiedEmail(mixed $providerId, array $inEvent): bool
    {
        if (!\is_string($providerId)) {
            return true;
        }

        $hexId = Uuid::fromBytesToHex($providerId);

        if (\array_key_exists($hexId, $inEvent)) {
            return $inEvent[$hexId];
        }

        $stored = $this->connection->fetchOne(
            'SELECT `require_email_verified` FROM `sw6oidc_provider` WHERE `id` = :id',
            ['id' => $providerId],
            ['id' => ParameterType::BINARY],
        );

        // Unknown provider: the database default.
        return $stored === false || (bool) $stored;
    }
}
