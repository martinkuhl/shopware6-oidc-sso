<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use Shopware\Core\Content\Media\File\MediaFile;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Downloads the picture claim through sw6oidc.http_client (M19), so the
 * avatar fetch gets the same SSRF guard as every other outbound IdP call
 * instead of depending on core's core.media.enableUrlValidation setting.
 * Only raster images up to MAX_BYTES; redirects are followed (avatar CDNs
 * use them) and each hop is IP-checked by the client.
 */
class AvatarFetcher
{
    public const MAX_BYTES = 2 * 1024 * 1024;
    private const MAX_REDIRECTS = 3;
    private const TIMEOUT_SECONDS = 5;
    /** `timeout` is an idle timeout; a slow-drip server must not stall the login (R3-L22). */
    private const MAX_DURATION_SECONDS = 10;

    private const EXTENSIONS = [
        'image/png' => 'png',
        'image/jpeg' => 'jpg',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
    ];

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly SsrfUrlValidator $urlValidator,
    ) {
    }

    /**
     * @throws \RuntimeException on any failure (the caller logs and keeps the old avatar)
     */
    public function fetch(string $url, string $tempFile): MediaFile
    {
        if ($this->urlValidator->validate($url)['blocked']) {
            throw new \RuntimeException('The avatar URL is not allowed.');
        }

        $response = $this->httpClient->request('GET', $url, [
            'max_redirects' => self::MAX_REDIRECTS,
            'timeout' => self::TIMEOUT_SECONDS,
            'max_duration' => self::MAX_DURATION_SECONDS,
            'headers' => ['Accept' => implode(', ', array_keys(self::EXTENSIONS))],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new \RuntimeException(sprintf('Avatar request answered HTTP %d.', $response->getStatusCode()));
        }

        $mimeType = strtolower(trim(explode(';', $response->getHeaders()['content-type'][0] ?? '')[0]));
        $extension = self::EXTENSIONS[$mimeType] ?? null;

        if ($extension === null) {
            throw new \RuntimeException(sprintf('Avatar has an unsupported content type "%s".', $mimeType));
        }

        $handle = fopen($tempFile, 'wb');

        if ($handle === false) {
            throw new \RuntimeException('Could not open the avatar temp file.');
        }

        $size = 0;

        try {
            foreach ($this->httpClient->stream($response) as $chunk) {
                $size += \strlen($chunk->getContent());

                if ($size > self::MAX_BYTES) {
                    $response->cancel();

                    throw new \RuntimeException('Avatar exceeds the size limit.');
                }

                fwrite($handle, $chunk->getContent());
            }
        } finally {
            fclose($handle);
        }

        if ($size === 0) {
            throw new \RuntimeException('Avatar is empty.');
        }

        // The file becomes public media: its type comes from its bytes, not
        // from a header the remote server chose (R3-L22).
        $sniffed = @getimagesize($tempFile);
        $mimeType = \is_array($sniffed) ? strtolower($sniffed['mime']) : '';
        $extension = self::EXTENSIONS[$mimeType] ?? null;

        if ($extension === null) {
            throw new \RuntimeException('Avatar content is not a PNG, JPEG, GIF or WebP image.');
        }

        return new MediaFile($tempFile, $mimeType, $extension, $size, hash_file('md5', $tempFile) ?: null);
    }
}
