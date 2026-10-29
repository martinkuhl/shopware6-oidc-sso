<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\AdminAuth;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminAuthorizationServerFactory;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminOidcGrant;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminTokenIssuer;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtPayloadReader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Runs the real League AuthorizationServer with the real grant (R3-H1,
 * R4-L7). Only the repositories are in-memory doubles. The issuer must not
 * depend on anything the client sends: before the fix, a JSON request lost
 * the grant type in the PSR bridge and every passkey login and step-up
 * failed with `unsupported_grant_type`.
 */
#[CoversClass(AdminTokenIssuer::class)]
final class AdminTokenIssuerTest extends TestCase
{
    public function testIssuesAccessAndRefreshTokenForTheUser(): void
    {
        $userId = Uuid::randomHex();

        $response = $this->issuer()->issue($userId);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertSame('Bearer', $payload['token_type']);
        self::assertIsString($payload['access_token']);
        self::assertArrayHasKey('refresh_token', $payload);
        self::assertSame($userId, JwtPayloadReader::stringClaim($payload['access_token'], 'sub'));
        self::assertSame(['write'], $this->scopes($payload['access_token']));
    }

    public function testStepUpTokenCarriesUserVerifiedAndNoRefreshToken(): void
    {
        $response = $this->issuer()->issue(Uuid::randomHex(), true);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getContent());
        $payload = json_decode((string) $response->getContent(), true);
        self::assertIsArray($payload);
        self::assertArrayNotHasKey('refresh_token', $payload);
        self::assertLessThanOrEqual(300, $payload['expires_in']);
        self::assertSame(['user-verified', 'write'], $this->scopes($payload['access_token']));
    }

    private function issuer(): AdminTokenIssuer
    {
        $connection = $this->createStub(Connection::class);
        $connection->method('fetchOne')->willReturn('1');

        $refreshTokens = new class implements RefreshTokenRepositoryInterface {
            public function getNewRefreshToken(): RefreshTokenEntityInterface
            {
                return new class implements RefreshTokenEntityInterface {
                    use EntityTrait;
                    use RefreshTokenTrait;
                };
            }

            public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
            {
            }

            public function revokeRefreshToken(string $tokenId): void
            {
            }

            public function isRefreshTokenRevoked(string $tokenId): bool
            {
                return false;
            }
        };

        $factory = new AdminAuthorizationServerFactory(
            $this->clients(),
            $this->accessTokens(),
            $this->scopeRepository(),
            new CryptKey($this->privateKey(), null, false),
            base64_encode(random_bytes(32)),
            new AdminOidcGrant($refreshTokens, $connection, 'P1W'),
            'PT10M',
        );

        return new AdminTokenIssuer($factory->create());
    }

    private function clients(): ClientRepositoryInterface
    {
        return new class implements ClientRepositoryInterface {
            public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
            {
                if ($clientIdentifier !== 'administration') {
                    return null;
                }

                return new class implements ClientEntityInterface {
                    use ClientTrait;
                    use EntityTrait;

                    public function __construct()
                    {
                        $this->identifier = 'administration';
                        $this->isConfidential = false;
                    }
                };
            }

            public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
            {
                return false;
            }
        };
    }

    private function accessTokens(): AccessTokenRepositoryInterface
    {
        return new class implements AccessTokenRepositoryInterface {
            public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
            {
                $token = new class implements AccessTokenEntityInterface {
                    use AccessTokenTrait;
                    use EntityTrait;
                    use TokenEntityTrait;
                };
                $token->setClient($clientEntity);

                foreach ($scopes as $scope) {
                    $token->addScope($scope);
                }

                if ($userIdentifier !== null) {
                    $token->setUserIdentifier($userIdentifier);
                }

                return $token;
            }

            public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
            {
            }

            public function revokeAccessToken(string $tokenId): void
            {
            }

            public function isAccessTokenRevoked(string $tokenId): bool
            {
                return false;
            }
        };
    }

    private function scopeRepository(): ScopeRepositoryInterface
    {
        return new class implements ScopeRepositoryInterface {
            public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
            {
                if (!\in_array($identifier, ['write', 'user-verified'], true)) {
                    return null;
                }

                $scope = new class implements ScopeEntityInterface {
                    use EntityTrait;
                    use ScopeTrait;
                };
                $scope->setIdentifier($identifier);

                return $scope;
            }

            public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
            {
                return $scopes;
            }
        };
    }

    /**
     * @return list<string>
     */
    private function scopes(string $accessToken): array
    {
        $parts = explode('.', $accessToken);
        $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);
        self::assertIsArray($claims);
        $scopes = $claims['scopes'];
        self::assertIsArray($scopes);
        sort($scopes);

        return array_values(array_map('strval', $scopes));
    }

    private function privateKey(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);
        self::assertIsString($pem);

        return $pem;
    }
}
