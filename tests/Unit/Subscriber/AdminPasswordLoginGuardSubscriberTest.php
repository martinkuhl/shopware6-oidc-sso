<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use MartinKuhl\Sw6Oidc\Subscriber\AdminPasswordLoginGuardSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

#[CoversClass(AdminPasswordLoginGuardSubscriber::class)]
final class AdminPasswordLoginGuardSubscriberTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, string>, array<string, string>, bool}>
     */
    public static function requests(): iterable
    {
        yield 'password grant' => [['grant_type' => 'password', 'username' => 'a', 'password' => 'b'], [], true];
        yield 'user access key' => [['grant_type' => 'client_credentials', 'client_id' => 'SWUAABC', 'client_secret' => 's'], [], true];
        // R3-M20: League trims client_id and falls back to Basic auth when it is empty.
        yield 'padded user access key' => [['grant_type' => 'client_credentials', 'client_id' => ' SWUAABC', 'client_secret' => 's'], [], true];
        yield 'empty client_id plus Basic auth' => [['grant_type' => 'client_credentials', 'client_id' => ''], ['PHP_AUTH_USER' => 'SWUAABC', 'PHP_AUTH_PW' => 's'], true];
        yield 'integration key' => [['grant_type' => 'client_credentials', 'client_id' => 'SWIAABC', 'client_secret' => 's'], [], false];
        yield 'refresh token' => [['grant_type' => 'refresh_token', 'refresh_token' => 'x'], [], false];
    }

    /**
     * @param array<string, string> $body
     * @param array<string, string> $server
     */
    #[DataProvider('requests')]
    public function testSsoOnlyModeAnswersNonSsoLoginsWith403(array $body, array $server, bool $refused): void
    {
        $request = Request::create('/api/oauth/token', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json', ...$server], json_encode($body, JSON_THROW_ON_ERROR));
        $request->attributes->set('_route', 'api.oauth.token');

        $policy = $this->createStub(PasswordLoginPolicy::class);
        $policy->method('isPasswordLoginDisabled')->willReturn(true);

        $event = new RequestEvent($this->createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
        (new AdminPasswordLoginGuardSubscriber($policy))->onRequest($event);

        self::assertSame($refused ? 403 : null, $event->getResponse()?->getStatusCode());
    }
}
