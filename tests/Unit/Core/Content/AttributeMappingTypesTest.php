<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Core\Content;

use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Sw6OidcAttributeMappingDefinition::class)]
final class AttributeMappingTypesTest extends TestCase
{
    /**
     * R8-L27: the Choice list is every TYPE_* constant, so adding a type can't
     * forget to allow it (or the other way round).
     */
    public function testTheChoiceListIsExactlyTheTypeConstants(): void
    {
        $constants = array_filter(
            (new \ReflectionClass(Sw6OidcAttributeMappingDefinition::class))->getConstants(),
            static fn (string $name): bool => str_starts_with($name, 'TYPE_'),
            \ARRAY_FILTER_USE_KEY,
        );

        self::assertEqualsCanonicalizing(array_values($constants), Sw6OidcAttributeMappingDefinition::TYPES);
    }
}
