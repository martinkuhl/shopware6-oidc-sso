<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Error responses for endpoints reachable by untrusted callers: a fixed
 * error code plus a random reference, never the exception text (which can
 * reveal issuers, client ids, internal URLs or which check failed). The
 * detail is logged under the same reference, so support can correlate.
 */
final class PublicError
{
    /**
     * @param array<string, mixed> $logContext
     */
    public static function response(
        LoggerInterface $logger,
        string $logMessage,
        \Throwable $exception,
        string $errorCode,
        int $status,
        array $logContext = [],
    ): JsonResponse {
        $reference = bin2hex(random_bytes(6));

        $logger->warning($logMessage, [
            ...$logContext,
            'errorReference' => $reference,
            'exceptionClass' => $exception::class,
            'exception' => $exception->getMessage(),
            'previousException' => $exception->getPrevious()?->getMessage(),
        ]);

        return new JsonResponse(['error' => $errorCode, 'errorReference' => $reference], $status);
    }
}
