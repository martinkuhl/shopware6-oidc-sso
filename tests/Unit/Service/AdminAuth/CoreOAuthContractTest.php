<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\OAuth\AccessTokenRepository;
use Shopware\Core\Framework\Api\OAuth\ClientRepository;
use Shopware\Core\Framework\Api\OAuth\FakeCryptKey;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\Framework\Api\OAuth\Scope\UserVerifiedScope;
use Shopware\Core\Framework\Api\OAuth\ScopeRepository;
use Shopware\Core\Framework\Api\OAuth\User\User;
use Shopware\Core\Framework\Api\OAuth\UserRepository;

/**
 * The admin bridge builds a second League AuthorizationServer on Shopware
 * core's OAuth services, several of them `@internal` or
 * `#[BecomesInternal('v6.8.0')]` (R3-L49). The plugin's own code only types
 * against League interfaces; this test pins everything it still needs from
 * core, so a Shopware update that moves one fails here, not at a login.
 */
#[CoversNothing]
final class CoreOAuthContractTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function coreServices(): iterable
    {
        yield 'client repository' => [ClientRepository::class, ClientRepositoryInterface::class];
        yield 'access token repository' => [AccessTokenRepository::class, AccessTokenRepositoryInterface::class];
        yield 'scope repository' => [ScopeRepository::class, ScopeRepositoryInterface::class];
        yield 'refresh token repository' => [RefreshTokenRepository::class, RefreshTokenRepositoryInterface::class];
        yield 'user repository' => [UserRepository::class, UserRepositoryInterface::class];
        yield 'crypt key' => [FakeCryptKey::class, CryptKeyInterface::class];
    }

    #[DataProvider('coreServices')]
    public function testTheCoreServicesStillImplementTheLeagueInterfaces(string $coreClass, string $leagueInterface): void
    {
        self::assertTrue(is_a($coreClass, $leagueInterface, true), $coreClass);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function coreMembers(): iterable
    {
        // Sw6OidcSessionDestructionService, PasswordSessionRevoker
        yield 'refresh token revocation' => [RefreshTokenRepository::class . '::revokeRefreshTokensForUser'];
        // AdminOidcGrant: finalizes scopes exactly like a password login
        yield 'password grant scopes' => [ScopeRepository::class . '::PASSWORD_GRANT'];
    }

    #[DataProvider('coreMembers')]
    public function testTheCoreMembersTheBridgeUsesStillExist(string $member): void
    {
        [$class, $name] = explode('::', $member);

        self::assertTrue(method_exists($class, $name) || \defined($member), $member);
    }

    public function testTheCoreUserAndScopeStillExist(): void
    {
        // AdminOidcGrant issues core's user; step-up tokens carry this scope.
        self::assertSame('user-verified', UserVerifiedScope::IDENTIFIER);
        self::assertSame('u1', (new User('u1'))->getIdentifier());
    }
}
