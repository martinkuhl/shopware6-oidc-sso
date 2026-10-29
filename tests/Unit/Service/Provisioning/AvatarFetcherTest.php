<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Service\Provisioning\AvatarFetcher;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[CoversClass(AvatarFetcher::class)]
final class AvatarFetcherTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = (string) tempnam(sys_get_temp_dir(), 'sw6oidc_avatar_test_');
    }

    protected function tearDown(): void
    {
        if (is_file($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    public function testDownloadsAnImage(): void
    {
        $png = self::png();
        $file = $this->fetcher(new MockResponse($png, ['response_headers' => ['content-type' => 'image/png; charset=binary']]))
            ->fetch('https://idp.example/a.png', $this->tempFile);

        self::assertSame('image/png', $file->getMimeType());
        self::assertSame('png', $file->getFileExtension());
        self::assertSame(\strlen($png), $file->getFileSize());
        self::assertSame($png, file_get_contents($this->tempFile));
    }

    public function testTheTypeComesFromTheBytesNotTheHeader(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not a PNG, JPEG, GIF or WebP');

        // An HTML page sent as image/png must never become public media (R3-L22).
        $this->fetcher(new MockResponse('<html><script>x</script></html>', ['response_headers' => ['content-type' => 'image/png']]))
            ->fetch('https://idp.example/a.png', $this->tempFile);
    }

    private static function png(): string
    {
        return (string) base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', true);
    }

    public function testRejectsNonImages(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('content type');

        $this->fetcher(new MockResponse('<svg/>', ['response_headers' => ['content-type' => 'image/svg+xml']]))
            ->fetch('https://idp.example/a.svg', $this->tempFile);
    }

    public function testRejectsOversizedImages(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('size limit');

        $this->fetcher(new MockResponse(str_repeat('x', AvatarFetcher::MAX_BYTES + 1), ['response_headers' => ['content-type' => 'image/jpeg']]))
            ->fetch('https://idp.example/a.jpg', $this->tempFile);
    }

    public function testRejectsHttpErrors(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->fetcher(new MockResponse('', ['http_code' => 404]))->fetch('https://idp.example/a.png', $this->tempFile);
    }

    public function testRejectsBlockedUrlsWithoutARequest(): void
    {
        $client = new MockHttpClient(static fn (): MockResponse => throw new \LogicException('must not be called'));
        $fetcher = new AvatarFetcher($client, new SsrfUrlValidator(false, static fn (): array => ['10.0.0.1']));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not allowed');

        $fetcher->fetch('https://intranet.example/a.png', $this->tempFile);
    }

    private function fetcher(MockResponse $response): AvatarFetcher
    {
        return new AvatarFetcher(new MockHttpClient($response), new SsrfUrlValidator(false, static fn (): array => ['93.184.216.34']));
    }
}
