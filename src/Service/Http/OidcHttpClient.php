<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Http;

use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Thin wrapper around Symfony's HttpClientInterface for the token/userinfo/
 * discovery calls the OIDC flow needs. Idempotent GETs are retried once,
 * 500 ms after a transport error; POSTs never are (see requestJson()).
 */
class OidcHttpClient
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param array<string, string> $formParams
     * @param int|null              $maxDurationSeconds cap on the whole request (`timeout` alone is an idle timeout)
     *
     * @return array<string, mixed>
     */
    public function postForm(
        string $url,
        array $formParams,
        int $timeoutSeconds,
        ?string $basicAuthUsername = null,
        ?string $basicAuthPassword = null,
        ?int $maxDurationSeconds = null,
    ): array {
        return $this->requestJson('POST', $url, $this->formOptions($formParams, $timeoutSeconds, $basicAuthUsername, $basicAuthPassword, $maxDurationSeconds));
    }

    /**
     * POST for endpoints whose success answer has no meaningful body, like
     * RFC 7009 revocation (§2.2: HTTP 200, the content is ignored — Authelia
     * sends an empty body). Only the status code decides.
     *
     * @param array<string, string> $formParams
     * @param int|null              $maxDurationSeconds cap on the whole request (`timeout` alone is an idle timeout)
     */
    public function postFormIgnoringResponseBody(
        string $url,
        array $formParams,
        int $timeoutSeconds,
        ?string $basicAuthUsername = null,
        ?string $basicAuthPassword = null,
        ?int $maxDurationSeconds = null,
    ): void {
        $options = $this->formOptions($formParams, $timeoutSeconds, $basicAuthUsername, $basicAuthPassword, $maxDurationSeconds);
        [, $statusCode] = $this->send('POST', $url, $options);

        $this->logResponse('POST', $url, $statusCode, null);

        if ($statusCode >= 400) {
            throw new OidcHttpException(sprintf('OIDC HTTP request to "%s" failed with status %d.', $this->withoutQuery($url), $statusCode));
        }
    }

    /**
     * @param array<string, string> $formParams
     *
     * @return array<string, mixed>
     */
    private function formOptions(
        array $formParams,
        int $timeoutSeconds,
        ?string $basicAuthUsername,
        ?string $basicAuthPassword,
        ?int $maxDurationSeconds,
    ): array {
        $headers = ['Accept' => 'application/json'];

        if ($basicAuthUsername !== null) {
            $headers['Authorization'] = 'Basic ' . base64_encode($basicAuthUsername . ':' . ($basicAuthPassword ?? ''));
        }

        $options = [
            'body' => $formParams,
            'timeout' => $timeoutSeconds,
            'headers' => $headers,
        ];

        if ($maxDurationSeconds !== null) {
            $options['max_duration'] = $maxDurationSeconds;
        }

        return $options;
    }

    /**
     * @return array<string, mixed>
     */
    public function getWithBearerToken(string $url, string $bearerToken, int $timeoutSeconds): array
    {
        return $this->requestJson('GET', $url, [
            'timeout' => $timeoutSeconds,
            'headers' => [
                'Authorization' => 'Bearer ' . $bearerToken,
                'Accept' => 'application/json',
            ],
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    public function getJson(string $url, int $timeoutSeconds): array
    {
        return $this->requestJson('GET', $url, [
            'timeout' => $timeoutSeconds,
            'headers' => ['Accept' => 'application/json'],
        ]);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    private function requestJson(string $method, string $url, array $options): array
    {
        [$content, $statusCode] = $this->send($method, $url, $options);
        $decoded = json_decode($content, true);

        $this->logResponse($method, $url, $statusCode, $decoded);

        if ($statusCode >= 400) {
            throw new OidcHttpException(sprintf('OIDC HTTP request to "%s" failed with status %d.', $this->withoutQuery($url), $statusCode));
        }

        if (!\is_array($decoded)) {
            throw new OidcHttpException(sprintf('OIDC HTTP response from "%s" was not valid JSON.', $this->withoutQuery($url)));
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{0: string, 1: int} content and status code
     */
    private function send(string $method, string $url, array $options): array
    {
        // Only ever logs field *names*, never values - a userinfo response in
        // particular is arbitrary IdP-supplied PII (email, address, phone,
        // birthdate, ...) with no fixed set of key names to denylist the way
        // SensitiveDataProcessor does for known credential fields
        // (client_secret/code/code_verifier/*_token). $options['headers'] is
        // deliberately never logged at all - that's where a Basic-auth
        // Authorization header lives for a confidential client.
        $logUrl = $this->withoutQuery($url);

        $this->logger->debug('sw6oidc: sending IdP HTTP request.', [
            'method' => $method,
            'url' => $logUrl,
            'formParamKeys' => array_keys($options['body'] ?? []),
        ]);

        try {
            $response = $this->httpClient->request($method, $url, $options);
            $content = $response->getContent(false);
            $statusCode = $response->getStatusCode();
        } catch (HttpClientExceptionInterface $exception) {
            // Only idempotent GETs are retried: a POST to the token endpoint
            // carries a single-use authorization code that a retry would burn
            // (or replay, making the IdP revoke the session). A destination
            // the SSRF guard blocked stays blocked (M3).
            if ($method !== 'GET' || $this->isBlockedAddress($exception)) {
                throw new OidcHttpException(sprintf('OIDC HTTP request to "%s" failed.', $logUrl), $exception);
            }

            $this->logger->warning('sw6oidc: retrying HTTP request after transport error.', [
                'url' => $logUrl,
                'exceptionClass' => $exception::class,
            ]);

            return $this->retryOnce($method, $url, $options);
        }

        return [$content, $statusCode];
    }

    private function logResponse(string $method, string $url, int $statusCode, mixed $decoded): void
    {
        $this->logger->log($statusCode >= 400 ? 'warning' : 'debug', 'sw6oidc: received IdP HTTP response.', [
            'method' => $method,
            'url' => $this->withoutQuery($url),
            'statusCode' => $statusCode,
            'bodyKeys' => \is_array($decoded) ? array_keys($decoded) : null,
        ]);
    }

    private function withoutQuery(string $url): string
    {
        $position = strcspn($url, '?#');

        return substr($url, 0, $position);
    }

    private function isBlockedAddress(\Throwable $exception): bool
    {
        return str_contains($exception->getMessage(), ' is blocked for ');
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{0: string, 1: int}
     */
    private function retryOnce(string $method, string $url, array $options): array
    {
        usleep(500_000);

        try {
            $response = $this->httpClient->request($method, $url, $options);

            return [$response->getContent(false), $response->getStatusCode()];
        } catch (HttpClientExceptionInterface $exception) {
            throw new OidcHttpException(sprintf('OIDC HTTP request to "%s" failed.', $this->withoutQuery($url)), $exception);
        }
    }
}
