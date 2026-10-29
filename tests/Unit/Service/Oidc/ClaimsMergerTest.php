<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsMerger;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClaimsMerger::class)]
final class ClaimsMergerTest extends TestCase
{
    public function testIdentityClaimsComeFromTheIdToken(): void
    {
        $merged = ClaimsMerger::merge(
            ['sub' => 's1', 'email' => 'a@example.com', 'email_verified' => true],
            ['sub' => 's1', 'email' => 'b@example.com', 'email_verified' => false, 'name' => 'Ann'],
        );

        self::assertSame(['sub' => 's1', 'email' => 'a@example.com', 'email_verified' => true, 'name' => 'Ann'], $merged);
    }

    public function testUserinfoForAnotherSubjectIsRefused(): void
    {
        $this->expectException(InvalidStateException::class);

        ClaimsMerger::merge(['sub' => 's1'], ['sub' => 's2']);
    }

    public function testRequireSubjectReturnsIt(): void
    {
        self::assertSame('s1', ClaimsMerger::requireSubject(['sub' => 's1']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function claimsWithoutSubject(): iterable
    {
        yield 'missing' => [['email' => 'a@example.com']];
        yield 'empty' => [['sub' => '']];
        yield 'not a string' => [['sub' => 42]];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('claimsWithoutSubject')]
    public function testClaimsWithoutSubjectAreRefused(array $claims): void
    {
        $this->expectException(InvalidStateException::class);
        $this->expectExceptionMessage('"sub"');

        ClaimsMerger::requireSubject($claims);
    }
}
