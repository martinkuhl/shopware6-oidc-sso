<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Http;

use MartinKuhl\Sw6Oidc\Service\Http\Sw6OidcHttpClientFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * R3-M2: redirects stay off behind the SSRF wrapper (which follows them
 * itself); a caller can still allow them per request (avatar downloads).
 */
#[CoversClass(Sw6OidcHttpClientFactory::class)]
final class Sw6OidcHttpClientFactoryTest extends TestCase
{
    /** @var list<string> */
    private array $requested = [];

    public function testRedirectsAreNotFollowedBehindTheSsrfWrapper(): void
    {
        $response = Sw6OidcHttpClientFactory::create($this->redirectingClient(), false)
            ->request('POST', 'https://93.184.215.14/token', ['body' => 'code=secret']);

        self::assertSame(307, $response->getStatusCode());
        self::assertSame(['https://93.184.215.14/token'], $this->requested, 'the code must not be re-posted to the redirect target');
    }

    public function testACallerCanAllowRedirectsPerRequest(): void
    {
        $response = Sw6OidcHttpClientFactory::create($this->redirectingClient(), false)
            ->request('GET', 'https://93.184.215.14/avatar', ['max_redirects' => 3]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['https://93.184.215.14/avatar', 'https://93.184.215.15/elsewhere'], $this->requested);
    }

    private function redirectingClient(): MockHttpClient
    {
        return new MockHttpClient(function (string $method, string $url): MockResponse {
            $this->requested[] = $url;

            if (str_ends_with($url, '/elsewhere')) {
                return new MockResponse('ok', ['http_code' => 200]);
            }

            return new MockResponse('', [
                'http_code' => 307,
                'response_headers' => ['Location' => 'https://93.184.215.15/elsewhere'],
                // what a real client reports; the SSRF wrapper follows it itself
                'redirect_url' => 'https://93.184.215.15/elsewhere',
            ]);
        });
    }
}
