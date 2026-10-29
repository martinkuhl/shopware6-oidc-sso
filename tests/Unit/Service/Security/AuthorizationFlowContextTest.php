<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationFlowContext::class)]
final class AuthorizationFlowContextTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $flow = new AuthorizationFlowContext('p', 'admin', '/x', 'v', 'S256', 'n', AuthorizationFlowContext::PURPOSE_LINK, 'user-1', 1700000000);

        self::assertEquals($flow, AuthorizationFlowContext::fromArray($flow->toArray()));
    }

    public function testLegacyEntryWithoutPurposeIsALogin(): void
    {
        $flow = AuthorizationFlowContext::fromArray(['providerId' => 'p', 'loginType' => 'customer', 'relayState' => '', 'codeVerifier' => 'v', 'codeChallengeMethod' => 'S256', 'nonce' => 'n']);

        self::assertSame(AuthorizationFlowContext::PURPOSE_LOGIN, $flow->purpose);
        self::assertNull($flow->expectedUserId);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function malformed(): iterable
    {
        $valid = ['providerId' => 'p', 'loginType' => 'customer', 'relayState' => '', 'codeVerifier' => 'v', 'codeChallengeMethod' => 'S256', 'nonce' => 'n'];

        yield 'missing key' => [array_diff_key($valid, ['nonce' => true])];
        yield 'non-string value' => [['providerId' => 1] + $valid];
        yield 'unknown login type' => [['loginType' => 'root'] + $valid];
        yield 'unknown purpose' => [['purpose' => 'impersonate'] + $valid];
        yield 'link without user' => [['purpose' => AuthorizationFlowContext::PURPOSE_LINK] + $valid];
        yield 'bad startedAt' => [['startedAt' => 'now'] + $valid];
    }

    /**
     * @param array<string, mixed> $data
     */
    #[DataProvider('malformed')]
    public function testMalformedEntriesAreRejected(array $data): void
    {
        $this->expectException(InvalidStateException::class);

        AuthorizationFlowContext::fromArray($data);
    }
}
