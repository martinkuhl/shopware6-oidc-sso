<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Oidc\ClaimsNormalizer;
use MartinKuhl\Sw6Oidc\Service\Oidc\Exception\ClaimsTooComplexException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClaimsNormalizer::class)]
final class ClaimsNormalizerTest extends TestCase
{
    private ClaimsNormalizer $normalizer;

    protected function setUp(): void
    {
        $this->normalizer = new ClaimsNormalizer();
    }

    public function testFlattenUsesDotNotationForNestedObjectsAndLists(): void
    {
        $flattened = $this->normalizer->flatten([
            'sub' => 'user-1',
            'email_verified' => true,
            'address' => ['street_address' => 'Main St 1', 'country' => 'DE'],
            'groups' => ['Engineering', 'Developers'],
        ]);

        self::assertSame([
            'sub' => 'user-1',
            'email_verified' => true,
            'address.street_address' => 'Main St 1',
            'address.country' => 'DE',
            'groups.0' => 'Engineering',
            'groups.1' => 'Developers',
        ], $flattened);
    }

    public function testFlattenKeepsNonStringScalarsAndNull(): void
    {
        $flattened = $this->normalizer->flatten(['age' => 42, 'ratio' => 1.5, 'nickname' => null]);

        self::assertSame(['age' => 42, 'ratio' => 1.5, 'nickname' => null], $flattened);
    }

    public function testFlattenDropsValuesBeyondMaxDepth(): void
    {
        $flattened = $this->normalizer->flatten([
            'l1' => ['l2' => ['l3' => ['l4' => ['l5' => [
                'l6' => 'kept',
                'l6b' => ['l7' => 'dropped'],
            ]]]]],
        ]);

        self::assertSame(['l1.l2.l3.l4.l5.l6' => 'kept'], $flattened);
    }

    public function testFlattenAcceptsLargeButBoundedClaimSet(): void
    {
        $claims = [];
        for ($i = 0; $i < 2000; ++$i) {
            $claims['claim' . $i] = 'v';
        }

        self::assertCount(2000, $this->normalizer->flatten($claims));
    }

    public function testFlattenRejectsOneKeyOverTheLimit(): void
    {
        $claims = [];
        for ($i = 0; $i < 2001; ++$i) {
            $claims['claim' . $i] = 'v';
        }

        $this->expectException(ClaimsTooComplexException::class);
        $this->normalizer->flatten($claims);
    }

    public function testFlattenThrowsWhenTooManyKeys(): void
    {
        $claims = [];
        for ($i = 0; $i < 2500; ++$i) {
            $claims['claim' . $i] = 'v';
        }

        $this->expectException(ClaimsTooComplexException::class);
        $this->normalizer->flatten($claims);
    }

    public function testFlattenThrowsWhenNestedClaimsExceedKeyLimit(): void
    {
        $claims = [];
        for ($i = 0; $i < 50; ++$i) {
            for ($j = 0; $j < 50; ++$j) {
                $claims['group' . $i]['item' . $j] = 'v';
            }
        }

        $this->expectException(ClaimsTooComplexException::class);
        $this->normalizer->flatten($claims);
    }

    public function testFlattenDecodesOnlyListedClaimsAndTheirChildren(): void
    {
        $flattened = $this->normalizer->flatten([
            'given_name' => base64_encode('Jürgen'),
            'org' => ['name' => base64_encode('ACME GmbH')],
            'organisation' => 'YWJj',
            'nickname' => 'YWJj',
        ], ['given_name', 'org']);

        self::assertSame('Jürgen', $flattened['given_name']);
        self::assertSame('ACME GmbH', $flattened['org.name']);
        self::assertSame('YWJj', $flattened['organisation'], 'a name prefix is not a parent');
        self::assertSame('YWJj', $flattened['nickname'], 'plain claims that happen to be valid base64 stay untouched (M10)');
    }

    public function testWildcardDecodesEveryClaim(): void
    {
        self::assertSame(['a' => 'abc', 'b.c' => 'abc'], $this->normalizer->flatten(['a' => 'YWJj', 'b' => ['c' => 'YWJj']], ['*']));
    }

    public function testDecodeGroupsOnlyWhenTheGroupClaimIsListed(): void
    {
        $groups = [base64_encode('Admins'), base64_encode('Staff')];

        self::assertSame(['Admins', 'Staff'], $this->normalizer->decodeGroups($groups, 'groups', ['groups']));
        self::assertSame(['Admins', 'Staff'], $this->normalizer->decodeGroups($groups, 'groups', ['*']));
        self::assertSame($groups, $this->normalizer->decodeGroups($groups, 'groups', ['given_name']));
    }

    public function testFlattenLeavesInvalidBase64AndNonUtf8ResultsUntouched(): void
    {
        $binary = base64_encode("\xFF\xFE\xFD");

        $flattened = $this->normalizer->flatten([
            'email' => 'user@example.com',
            'binary' => $binary,
            'empty' => '',
            'number' => 7,
        ], ['*']);

        self::assertSame('user@example.com', $flattened['email']);
        self::assertSame($binary, $flattened['binary']);
        self::assertSame('', $flattened['empty']);
        self::assertSame(7, $flattened['number']);
    }

    public function testFlattenDoesNotDecodeWithoutBase64Encoding(): void
    {
        $encoded = base64_encode('Jürgen');

        self::assertSame(['given_name' => $encoded], $this->normalizer->flatten(['given_name' => $encoded]));
    }

    public function testNormalizeGroupsPlainList(): void
    {
        self::assertSame(['Engineering', 'Developers'], $this->normalizer->normalizeGroups(['Engineering', 'Developers']));
    }

    public function testNormalizeGroupsListKeepsIntegerIdsAndSkipsOtherNonStrings(): void
    {
        self::assertSame(['A', '42', 'B'], $this->normalizer->normalizeGroups(['A', 42, null, ['nested'], '', 1.5, 'B']));
    }

    public function testNormalizeGroupsKeepsAGroupNamedZero(): void
    {
        self::assertSame(['0', 'Eng'], $this->normalizer->normalizeGroups(['0', 'Eng']));
    }

    public function testNormalizeGroupsSingleStringIsNotSplitOnCommas(): void
    {
        self::assertSame(['Engineering'], $this->normalizer->normalizeGroups('Engineering'));
        self::assertSame(['Engineering,Developers'], $this->normalizer->normalizeGroups('Engineering,Developers'));
    }

    public function testNormalizeGroupsEmptyAndUnsupportedShapes(): void
    {
        self::assertSame([], $this->normalizer->normalizeGroups(''));
        self::assertSame([], $this->normalizer->normalizeGroups(null));
        self::assertSame([], $this->normalizer->normalizeGroups(42));
        self::assertSame([], $this->normalizer->normalizeGroups([]));
    }

    public function testNormalizeGroupsZitadelNestedRoleObject(): void
    {
        $groups = $this->normalizer->normalizeGroups([
            'Engineering' => ['123456789' => 'acme.zitadel.cloud'],
            'Admins' => ['orgId' => '987654321'],
        ]);

        self::assertSame(['Engineering', 'Admins'], $groups);
    }

    public function testNormalizeGroupsZitadelObjectWithNumericRoleKeyIsStringified(): void
    {
        self::assertSame(['0', 'Engineering'], $this->normalizer->normalizeGroups([
            '0' => ['orgId' => '1'],
            'Engineering' => ['orgId' => '2'],
        ]));
    }

    public function testObjectShapedBase64ClaimHasItsMemberNamesDecodedLikeGroups(): void
    {
        $roles = [base64_encode('Admins') => ['orgId' => '1'], base64_encode('Editors') => ['orgId' => '2']];

        $flattened = $this->normalizer->flatten(['roles' => $roles], ['roles']);
        $groups = $this->normalizer->decodeGroups($this->normalizer->normalizeGroups($roles), 'roles', ['roles']);

        // Access rules (flattened keys) and group mapping see the same names (R3-L6).
        self::assertSame(['roles.Admins.orgId', 'roles.Editors.orgId'], array_keys($flattened));
        self::assertSame(['Admins', 'Editors'], $groups);
    }

    public function testMemberNamesOfUnlistedClaimsStayEncoded(): void
    {
        $key = base64_encode('Admins');

        self::assertSame(['roles.' . $key . '.orgId'], array_keys($this->normalizer->flatten(['roles' => [$key => ['orgId' => '1']]], ['other'])));
    }
}
