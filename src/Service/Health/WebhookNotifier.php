<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * POSTs a health alert as JSON to the provider's webhook. The payload carries
 * a human-readable `text` (what Slack, Mattermost, Teams workflows and most
 * chat webhooks display) next to structured fields for other receivers.
 * Uses the SSRF-guarded plugin client and re-validates the URL first.
 */
class WebhookNotifier
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly SsrfUrlValidator $urlValidator,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function send(string $webhookUrl, array $payload): bool
    {
        $ssrf = $this->urlValidator->validate($webhookUrl);

        if ($ssrf['blocked']) {
            $this->logger->warning('sw6oidc: health alert webhook URL blocked.', ['warnings' => $ssrf['warnings']]);

            return false;
        }

        try {
            $status = $this->httpClient->request('POST', $webhookUrl, [
                'json' => $payload,
                'timeout' => 10,
            ])->getStatusCode();
        } catch (\Throwable $exception) {
            // Class and code only: transport messages contain the full URL,
            // and webhook URLs embed their token (N-L8).
            $this->logger->warning('sw6oidc: health alert webhook failed.', [
                'exceptionClass' => $exception::class,
                'exceptionCode' => $exception->getCode(),
            ]);

            return false;
        }

        if ($status >= 400) {
            $this->logger->warning('sw6oidc: health alert webhook answered with an error.', ['status' => $status]);

            return false;
        }

        return true;
    }
}
