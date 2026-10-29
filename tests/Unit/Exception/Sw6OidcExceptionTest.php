<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Exception;

use MartinKuhl\Sw6Oidc\Exception\Sw6OidcException;
use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyLimitReachedException;
use MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AdminProvisioningDeniedException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\UnknownStateException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\HttpException;

#[CoversClass(Sw6OidcException::class)]
final class Sw6OidcExceptionTest extends TestCase
{
    /**
     * @return iterable<string, array{HttpException, int, string}>
     */
    public static function exceptions(): iterable
    {
        yield 'IdP request' => [new OidcHttpException('x'), 502, 'SW6OIDC_IDP_REQUEST_FAILED'];
        yield 'JWT' => [new InvalidJwtException('x', new \RuntimeException('inner')), 400, 'SW6OIDC_INVALID_JWT'];
        yield 'provider' => [new ProviderNotFoundException('x'), 404, 'SW6OIDC_PROVIDER_NOT_FOUND'];
        yield 'subclass overrides' => [new UnknownStateException('x'), 400, 'SW6OIDC_UNKNOWN_STATE'];
        yield 'passkey limit' => [new PasskeyLimitReachedException('x'), 409, 'SW6OIDC_PASSKEY_LIMIT_REACHED'];
        yield 'named constructor' => [AdminProvisioningDeniedException::accountInactive(), 403, 'SW6OIDC_ADMIN_PROVISIONING_DENIED'];
        yield 'custom constructor' => [new AccessControlDeniedException('r', 'groups', null), 403, 'SW6OIDC_ACCESS_DENIED'];
    }

    /**
     * R3-L10: an escaping domain exception is a typed error response with a
     * stable code, not an anonymous 500.
     */
    #[DataProvider('exceptions')]
    public function testDomainExceptionsAreShopwareHttpExceptions(HttpException $exception, int $status, string $code): void
    {
        self::assertInstanceOf(Sw6OidcException::class, $exception);
        self::assertSame($status, $exception->getStatusCode());
        self::assertSame($code, $exception->getErrorCode());
    }

    public function testThePreviousExceptionIsKept(): void
    {
        $previous = new \RuntimeException('inner');

        self::assertSame($previous, (new InvalidJwtException('outer', $previous))->getPrevious());
    }
}
