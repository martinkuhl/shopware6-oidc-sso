<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcCspHostCollector;
use MartinKuhl\Sw6Oidc\Subscriber\Sw6OidcCspSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\PlatformRequest;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

#[CoversClass(Sw6OidcCspHostCollector::class)]
#[CoversClass(Sw6OidcCspSubscriber::class)]
final class Sw6OidcCspTest extends TestCase
{
    public function testCollectsDeduplicatedHttpsOriginsOnly(): void
    {
        $collector = new Sw6OidcCspHostCollector($this->repositoryWith([
            $this->provider('https://IdP.example/authorize', 'https://idp.example/token', 'http://plain.example/userinfo'),
            $this->provider('https://other.example:8443/auth', null, null),
        ]), new ArrayAdapter());

        self::assertSame(['https://idp.example', 'https://other.example:8443'], $collector->collect(Context::createDefaultContext()));
    }

    public function testNoActiveProvidersYieldsNothing(): void
    {
        self::assertSame([], (new Sw6OidcCspHostCollector($this->repositoryWith([]), new ArrayAdapter()))->collect(Context::createDefaultContext()));
    }

    public function testResultIsCachedUntilInvalidated(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::exactly(2))->method('search')->willReturnCallback(fn (Criteria $c, Context $ctx) => $this->searchResult([], $c, $ctx));
        $collector = new Sw6OidcCspHostCollector($repository, new ArrayAdapter());

        $collector->collect(Context::createDefaultContext());
        $collector->collect(Context::createDefaultContext());
        $collector->invalidate();
        $collector->collect(Context::createDefaultContext());
    }

    public function testAppendsOnlyToExistingDirectivesAndNeverToNone(): void
    {
        $policy = "default-src 'self'; form-action 'self'; img-src 'self' data:; frame-src 'none'";

        self::assertSame(
            "default-src 'self'; form-action 'self' https://idp.example; img-src 'self' data: https://idp.example; frame-src 'none'",
            Sw6OidcCspSubscriber::appendHosts($policy, ['https://idp.example']),
        );
    }

    public function testDoesNotDuplicateHosts(): void
    {
        self::assertSame(
            'connect-src https://idp.example',
            Sw6OidcCspSubscriber::appendHosts('connect-src https://idp.example', ['https://idp.example']),
        );
    }

    public function testSubscriberLeavesResponsesWithoutPolicyOrOutsideScopeAlone(): void
    {
        $collector = new Sw6OidcCspHostCollector($this->repositoryWith([$this->provider('https://idp.example/a', null, null)]), new ArrayAdapter());
        $subscriber = new Sw6OidcCspSubscriber($collector);

        $noPolicy = $this->event(['storefront'], null);
        $subscriber->onResponse($noPolicy);
        self::assertFalse($noPolicy->getResponse()->headers->has('Content-Security-Policy'));

        $apiScope = $this->event(['api'], "connect-src 'self'");
        $subscriber->onResponse($apiScope);
        self::assertSame("connect-src 'self'", $apiScope->getResponse()->headers->get('Content-Security-Policy'));

        $storefront = $this->event(['storefront'], "connect-src 'self'");
        $subscriber->onResponse($storefront);
        self::assertSame("connect-src 'self' https://idp.example", $storefront->getResponse()->headers->get('Content-Security-Policy'));
    }

    public function testEveryPolicyHeaderAndReportOnlyAreExtended(): void
    {
        $collector = new Sw6OidcCspHostCollector($this->repositoryWith([$this->provider('https://idp.example/a', null, null)]), new ArrayAdapter());

        $event = $this->event(['storefront'], null);
        $headers = $event->getResponse()->headers;
        $headers->set('Content-Security-Policy', ["connect-src 'self'", "form-action 'self'; img-src 'none'"]);
        $headers->set('Content-Security-Policy-Report-Only', "frame-src 'self'");

        (new Sw6OidcCspSubscriber($collector))->onResponse($event);

        self::assertSame(
            ["connect-src 'self' https://idp.example", "form-action 'self' https://idp.example; img-src 'none'"],
            $headers->all('content-security-policy'),
            'a second, stricter policy is kept and extended, not dropped (N-L15)',
        );
        self::assertSame("frame-src 'self' https://idp.example", $headers->get('Content-Security-Policy-Report-Only'));
    }

    /**
     * @param list<string> $scopes
     */
    private function event(array $scopes, ?string $policy): ResponseEvent
    {
        $request = new Request();
        $request->attributes->set(PlatformRequest::ATTRIBUTE_ROUTE_SCOPE, $scopes);
        $response = new Response();

        if ($policy !== null) {
            $response->headers->set('Content-Security-Policy', $policy);
        }

        return new ResponseEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST, $response);
    }

    private function provider(?string $authorize, ?string $token, ?string $userInfo): Sw6OidcProviderEntity
    {
        $provider = new Sw6OidcProviderEntity();
        $provider->assign(['id' => Uuid::randomHex(), 'authorizeEndpoint' => $authorize, 'accessTokenEndpoint' => $token, 'userInfoEndpoint' => $userInfo]);

        return $provider;
    }

    /**
     * @param list<Sw6OidcProviderEntity> $providers
     */
    private function repositoryWith(array $providers): EntityRepository
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('search')->willReturnCallback(fn (Criteria $c, Context $ctx) => $this->searchResult($providers, $c, $ctx));

        return $repository;
    }

    /**
     * @param list<Sw6OidcProviderEntity> $providers
     */
    private function searchResult(array $providers, Criteria $criteria, Context $context): EntitySearchResult
    {
        return new EntitySearchResult(Sw6OidcProviderDefinition::ENTITY_NAME, \count($providers), new Sw6OidcProviderCollection($providers), null, $criteria, $context);
    }
}
