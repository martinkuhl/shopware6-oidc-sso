<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeTransformer as T;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

#[CoversClass(T::class)]
final class AttributeTransformerTest extends TestCase
{
    /**
     * @return iterable<string, array{?string, array<string, mixed>, ?string, ?string}>
     */
    public static function transforms(): iterable
    {
        yield 'no function' => [null, [], ' keep ', ' keep '];
        yield 'concat default separator' => [T::CONCAT, ['claims' => ['last']], 'Ada', 'Ada Lovelace'];
        yield 'concat custom separator, skips missing' => [T::CONCAT, ['claims' => ['missing', 'last'], 'separator' => ', '], 'Ada', 'Ada, Lovelace'];
        yield 'concat without own value' => [T::CONCAT, ['claims' => ['last']], null, 'Lovelace'];
        yield 'concat nothing to join' => [T::CONCAT, ['claims' => ['missing']], null, null];
        yield 'split first' => [T::SPLIT, ['separator' => '@', 'index' => 0], 'ada@example.com', 'ada'];
        yield 'split negative index' => [T::SPLIT, ['separator' => ' ', 'index' => -1], 'Ada King Lovelace', 'Lovelace'];
        yield 'split string index' => [T::SPLIT, ['separator' => ' ', 'index' => '1'], 'Ada King Lovelace', 'King'];
        yield 'split out of range' => [T::SPLIT, ['separator' => ' ', 'index' => 5], 'Ada', null];
        yield 'split null value' => [T::SPLIT, ['separator' => ' ', 'index' => 0], null, null];
        yield 'prefix' => [T::PREFIX, ['value' => 'OIDC-'], '42', 'OIDC-42'];
        yield 'prefix null value' => [T::PREFIX, ['value' => 'OIDC-'], null, null];
        yield 'regex replace' => [T::REGEX_REPLACE, ['pattern' => '/\D+/', 'replacement' => ''], '+49 (30) 1234', '49301234'];
        yield 'regex replace to empty' => [T::REGEX_REPLACE, ['pattern' => '/.*/'], 'gone', null];
    }

    /**
     * @param array<string, mixed> $params
     */
    #[DataProvider('transforms')]
    public function testTransforms(?string $function, array $params, ?string $value, ?string $expected): void
    {
        self::assertSame($expected, (new T(new NullLogger()))->apply($function, $params, $value, ['last' => 'Lovelace']));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, string}>
     */
    public static function brokenConfigurations(): iterable
    {
        yield 'unknown function' => ['uppercase', [], 'value'];
        yield 'concat claims not a list' => [T::CONCAT, ['claims' => 'last'], 'value'];
        yield 'split empty separator' => [T::SPLIT, ['separator' => '', 'index' => 0], 'a b'];
        yield 'split non-integer index' => [T::SPLIT, ['separator' => ' ', 'index' => 'first'], 'a b'];
        yield 'prefix non-scalar value' => [T::PREFIX, ['value' => ['x']], 'value'];
        yield 'regex invalid pattern' => [T::REGEX_REPLACE, ['pattern' => '/(unclosed'], 'value'];
        yield 'regex missing pattern' => [T::REGEX_REPLACE, [], 'value'];
        yield 'regex pattern too long' => [T::REGEX_REPLACE, ['pattern' => '/' . str_repeat('a', 4100) . '/'], 'value'];
        yield 'regex value too long' => [T::REGEX_REPLACE, ['pattern' => '/a/'], str_repeat('a', 4100)];
    }

    /**
     * @param array<string, mixed> $params
     */
    #[DataProvider('brokenConfigurations')]
    public function testBrokenConfigurationPassesTheValueThroughAndLogs(string $function, array $params, string $value): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning');

        self::assertSame($value, (new T($logger))->apply($function, $params, $value, []));
    }

    public function testCatastrophicBacktrackingPassesThrough(): void
    {
        $value = str_repeat('a', 4000) . '!';

        self::assertSame($value, (new T(new NullLogger()))->apply(T::REGEX_REPLACE, ['pattern' => '/(a+)+$/', 'replacement' => 'x'], $value, []));
    }

    public function testStrictModeRefusesInsteadOfPassingTheRawValueThrough(): void
    {
        $this->expectException(\MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AttributeTransformFailedException::class);

        (new T(new NullLogger()))->apply(T::REGEX_REPLACE, ['pattern' => '/(unclosed', 'replacement' => ''], 'Jane@Example.com', [], true);
    }

    public function testStrictModeStillTransformsNormally(): void
    {
        self::assertSame('jane@example.com', (new T(new NullLogger()))->apply(T::REGEX_REPLACE, ['pattern' => '/@EXAMPLE\.COM$/i', 'replacement' => '@example.com'], 'jane@EXAMPLE.COM', [], true));
    }
}
