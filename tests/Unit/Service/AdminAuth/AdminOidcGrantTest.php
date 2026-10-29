<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminOidcGrant;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * The grant trusts the caller for *who* the user is, but decides itself
 * whether that account may still log in (deleted / deactivated admins).
 */
#[CoversClass(AdminOidcGrant::class)]
final class AdminOidcGrantTest extends TestCase
{
    public function testActiveUserIsAccepted(): void
    {
        $userId = Uuid::randomHex();

        self::assertSame($userId, $this->validate($userId, '1')->getIdentifier());
    }

    public function testInactiveUserIsRejected(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->validate(Uuid::randomHex(), '0');
    }

    public function testDeletedUserIsRejected(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->validate(Uuid::randomHex(), false);
    }

    public function testMalformedUserIdIsRejectedWithoutQuerying(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->validate('not-a-uuid', '1', expectQuery: false);
    }

    public function testUserVerifiedIsStrippedFromRequestedScopes(): void
    {
        $grant = new AdminOidcGrant($this->createStub(RefreshTokenRepositoryInterface::class), $this->createStub(Connection::class), 'P1W');
        $method = new \ReflectionMethod($grant, 'withoutUserVerified');

        self::assertSame('write admin', $method->invoke($grant, 'write  user-verified admin'));
        self::assertSame('', $method->invoke($grant, 'user-verified'));
    }

    private function validate(string $userId, string|false $active, bool $expectQuery = true): \League\OAuth2\Server\Entities\UserEntityInterface
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects($expectQuery ? self::once() : self::never())->method('fetchOne')->willReturn($active);

        $grant = new AdminOidcGrant($this->createStub(RefreshTokenRepositoryInterface::class), $connection, 'P1W');
        $request = (new ServerRequest('POST', '/api/sw6oidc/admin/token'))->withAttribute(AdminOidcGrant::REQUEST_ATTRIBUTE_USER_ID, $userId);

        $method = new \ReflectionMethod($grant, 'validateUser');

        $user = $method->invoke($grant, $request);
        \assert($user instanceof \League\OAuth2\Server\Entities\UserEntityInterface);

        return $user;
    }
}
