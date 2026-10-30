<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Migration;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Migration\Migration1790900000CreateSchema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupDefinition;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\EntityDefinition;
use Shopware\Core\Framework\DataAbstractionLayer\Field\AssociationField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\CreatedAtField;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\Required;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Flag\WriteProtected;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StorageAware;
use Shopware\Core\Framework\DataAbstractionLayer\Write\EntityWriteGatewayInterface;
use Shopware\Core\Test\Stub\DataAbstractionLayer\StaticDefinitionInstanceRegistry;
use Symfony\Component\Validator\Validation;

/**
 * The one schema migration and the entity definitions describe the same
 * tables: every field has its column, every column its field, and a NOT NULL
 * column the API can write is `Required` — otherwise an API write of null or
 * "" ends in a database error instead of a validation error (R8-L21).
 */
#[CoversClass(Migration1790900000CreateSchema::class)]
final class SchemaMatchesDefinitionsTest extends TestCase
{
    private const DEFINITIONS = [
        Sw6OidcProviderDefinition::class,
        Sw6OidcAttributeMappingDefinition::class,
        Sw6OidcRoleMappingDefinition::class,
        Sw6OidcAccessControlRuleDefinition::class,
        Sw6OidcUserProviderDefinition::class,
        Sw6OidcPasskeyCredentialDefinition::class,
        Sw6OidcSessionActivityDefinition::class,
    ];

    /**
     * @return iterable<string, array{class-string<EntityDefinition>}>
     */
    public static function definitions(): iterable
    {
        foreach (self::DEFINITIONS as $class) {
            yield $class => [$class];
        }
    }

    /**
     * @param class-string<EntityDefinition> $class
     */
    #[DataProvider('definitions')]
    public function testDefinitionAndTableAgree(string $class): void
    {
        $definition = self::registry()->get($class);
        $columns = self::columns()[$definition->getEntityName()] ?? null;
        self::assertIsArray($columns, sprintf('No CREATE TABLE for %s.', $definition->getEntityName()));

        $fieldColumns = [];

        foreach ($definition->getFields() as $field) {
            if ($field instanceof AssociationField || !$field instanceof StorageAware) {
                continue;
            }

            $column = $field->getStorageName();
            $fieldColumns[] = $column;
            self::assertArrayHasKey($column, $columns, sprintf('%s.%s has no column.', $definition->getEntityName(), $column));

            // A column default doesn't help against an explicit null; only
            // fields the API can't write at all are exempt.
            if ($columns[$column] && !$field instanceof CreatedAtField && !$field->is(WriteProtected::class)) {
                self::assertTrue($field->is(Required::class), sprintf('%s.%s is NOT NULL, so the field must be Required.', $definition->getEntityName(), $column));
            }
        }

        self::assertSame([], array_values(array_diff(array_keys($columns), $fieldColumns)), sprintf('Columns of %s without a field.', $definition->getEntityName()));
    }

    /**
     * @return array<string, array<string, bool>> table => column => NOT NULL
     */
    private static function columns(): array
    {
        $tables = [];

        foreach (Migration1790900000CreateSchema::statements() as $statement) {
            self::assertSame(1, preg_match('/CREATE TABLE IF NOT EXISTS `(\w+)`/', $statement, $table));

            foreach (explode("\n", $statement) as $line) {
                if (preg_match('/^\s*`(\w+)` [A-Z]/', $line, $column) === 1) {
                    $tables[$table[1]][$column[1]] = str_contains($line, 'NOT NULL');
                }
            }
        }

        return $tables;
    }

    private static function registry(): StaticDefinitionInstanceRegistry
    {
        return new StaticDefinitionInstanceRegistry(
            [...self::DEFINITIONS, AclRoleDefinition::class, CustomerGroupDefinition::class],
            Validation::createValidator(),
            (new self('registry'))->createStub(EntityWriteGatewayInterface::class),
        );
    }
}
