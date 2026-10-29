<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Controller\Api;

use MartinKuhl\Sw6Oidc\Controller\Api\OidcUserProviderAdminController;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\HttpFoundation\Request;
use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSsoSchema;
use Shopware\Core\PlatformRequest;

#[CoversClass(OidcUserProviderAdminController::class)]
final class OidcUserProviderAdminControllerTest extends TestCase
{
    public function testInfoReturnsBindingsKeyedByUserId(): void
    {
        $userId = Uuid::randomHex();
        $providerId = Uuid::randomHex();
        $createdAt = new \DateTimeImmutable('2026-09-29T10:00:00+00:00');

        $provider = new Sw6OidcProviderEntity();
        $provider->setId($providerId);
        $provider->setAppName('keycloak');
        $provider->setDisplayName('Keycloak');

        $binding = new Sw6OidcUserProviderEntity();
        $binding->setId(Uuid::randomHex());
        $binding->setUserType(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER);
        $binding->setUserId($userId);
        $binding->setProviderId($providerId);
        $binding->setProvider($provider);
        $binding->setCreatedAt($createdAt);

        $controller = $this->controller($this->repositoryReturning([$binding]));
        $request = new Request(request: ['userType' => 'customer', 'userIds' => $userId . ',' . Uuid::randomHex() . ',not-a-uuid']);

        $response = $controller->info($request, $this->context(['customer:read']));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['bindings' => [$userId => [
                'providerId' => $providerId,
                'providerName' => 'Keycloak',
                'createdAt' => $createdAt->format(\DateTimeInterface::ATOM),
            ]]],
            json_decode((string) $response->getContent(), true),
        );
    }

    public function testInfoFallsBackToTechnicalProviderName(): void
    {
        $userId = Uuid::randomHex();

        $provider = new Sw6OidcProviderEntity();
        $provider->setId(Uuid::randomHex());
        $provider->setAppName('keycloak');

        $binding = new Sw6OidcUserProviderEntity();
        $binding->setId(Uuid::randomHex());
        $binding->setUserType(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN);
        $binding->setUserId($userId);
        $binding->setProviderId($provider->getId());
        $binding->setProvider($provider);

        $response = $this->controller($this->repositoryReturning([$binding]))
            ->info(new Request(request: ['userType' => 'admin', 'userIds' => $userId]), $this->context(['user:read']));

        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('keycloak', $body['bindings'][$userId]['providerName']);
    }

    public function testInfoRejectsUnknownUserType(): void
    {
        $response = $this->controller($this->createMock(EntityRepository::class))
            ->info(new Request(request: ['userType' => 'guest', 'userIds' => Uuid::randomHex()]), $this->context([], true));

        self::assertSame(400, $response->getStatusCode());
    }

    public function testInfoDeniesSourceWithoutReadPrivilegeOfThatUserType(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('search');

        $response = $this->controller($repository)
            ->info(new Request(request: ['userType' => 'customer', 'userIds' => Uuid::randomHex()]), $this->context(['user:read']));

        self::assertSame(403, $response->getStatusCode());
    }

    public function testInfoAllowsAdminToReadOwnBindingWithoutUserReadPrivilege(): void
    {
        $ownId = Uuid::randomHex();
        $source = new AdminApiSource($ownId);
        $source->setPermissions([]);
        $context = new Context($source);

        $repository = $this->repositoryReturning([]);

        self::assertSame(200, $this->controller($repository)
            ->info(new Request(request: ['userType' => 'admin', 'userIds' => $ownId]), $context)->getStatusCode());
        self::assertSame(403, $this->controller($repository)
            ->info(new Request(request: ['userType' => 'admin', 'userIds' => $ownId . ',' . Uuid::randomHex()]), $context)->getStatusCode());
        self::assertSame(403, $this->controller($repository)
            ->info(new Request(request: ['userType' => 'customer', 'userIds' => $ownId]), $context)->getStatusCode());
    }

    public function testUnlinkUnbindsWithUpdatePrivilege(): void
    {
        $userId = Uuid::randomHex();

        $bindingService = $this->createMock(UserProviderBindingService::class);
        $bindingService->expects(self::once())
            ->method('unbind')
            ->with(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $userId, self::isInstanceOf(Context::class));

        $response = $this->controller($this->createMock(EntityRepository::class), $bindingService)
            ->unlink($this->verifiedRequest(['userType' => 'admin', 'userId' => $userId]), $this->context(['user:update']));

        self::assertSame(204, $response->getStatusCode());
    }

    public function testUnlinkingAnAdminNeedsAUserVerifiedToken(): void
    {
        $bindingService = $this->createMock(UserProviderBindingService::class);
        $bindingService->expects(self::never())->method('unbind');

        $response = $this->controller($this->createMock(EntityRepository::class), $bindingService)
            ->unlink(new Request(request: ['userType' => 'admin', 'userId' => Uuid::randomHex()]), $this->context(['user:update']));

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('user_verification_required', (string) $response->getContent());
    }

    public function testUnlinkingTheLastSsoAdminIsRefusedUnderSsoOnlyMode(): void
    {
        $db = new SqliteSsoSchema();
        $provider = $db->provider(['disable_non_oidc_admin_login' => 1]);
        $admin = $db->admin();
        $db->bind($provider, $admin);

        $bindingService = $this->createMock(UserProviderBindingService::class);
        $bindingService->expects(self::never())->method('unbind');

        $response = $this->controller($this->createMock(EntityRepository::class), $bindingService, $db)
            ->unlink($this->verifiedRequest(['userType' => 'admin', 'userId' => $admin]), $this->context(['user:update']));

        self::assertSame(409, $response->getStatusCode());
    }

    public function testUnlinkDeniesSourceWithOnlyReadPrivilege(): void
    {
        $bindingService = $this->createMock(UserProviderBindingService::class);
        $bindingService->expects(self::never())->method('unbind');

        $response = $this->controller($this->createMock(EntityRepository::class), $bindingService)
            ->unlink(new Request(request: ['userType' => 'customer', 'userId' => Uuid::randomHex()]), $this->context(['customer:read']));

        self::assertSame(403, $response->getStatusCode());
    }

    public function testUnlinkRejectsInvalidUserId(): void
    {
        $response = $this->controller($this->createMock(EntityRepository::class))
            ->unlink(new Request(request: ['userType' => 'customer', 'userId' => 'nope']), $this->context([], true));

        self::assertSame(400, $response->getStatusCode());
    }

    private function controller(EntityRepository $repository, ?UserProviderBindingService $bindingService = null, ?SqliteSsoSchema $db = null): OidcUserProviderAdminController
    {
        return new OidcUserProviderAdminController(
            $repository,
            $bindingService ?? $this->createMock(UserProviderBindingService::class),
            new NullLogger(),
            new SsoOnlyInvariant(($db ?? new SqliteSsoSchema())->connection),
        );
    }

    /**
     * @param array<string, string> $body
     */
    private function verifiedRequest(array $body): Request
    {
        $request = new Request(request: $body);
        $request->attributes->set(PlatformRequest::ATTRIBUTE_OAUTH_SCOPES, ['write', 'user-verified']);

        return $request;
    }

    /**
     * @param list<string> $permissions
     */
    private function context(array $permissions, bool $isAdmin = false): Context
    {
        $source = new AdminApiSource(Uuid::randomHex());
        $source->setIsAdmin($isAdmin);
        $source->setPermissions($permissions);

        return new Context($source);
    }

    /**
     * @param list<Sw6OidcUserProviderEntity> $entities
     */
    private function repositoryReturning(array $entities): EntityRepository
    {
        $result = new EntitySearchResult(
            Sw6OidcUserProviderDefinition::ENTITY_NAME,
            \count($entities),
            new Sw6OidcUserProviderCollection($entities),
            null,
            new Criteria(),
            Context::createDefaultContext(),
        );

        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturn($result);

        return $repository;
    }
}
