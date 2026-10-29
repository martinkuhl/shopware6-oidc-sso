<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Logging;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Masks credentials before they reach the log file (H9, R3-L45):
 *
 * - context values under credential-like keys, in any spelling
 *   (client_secret, idToken, contextToken, sessionKey, apiKey, …) and of
 *   any type, recursively;
 * - inside any string, message included: credential parameters in query
 *   strings (also at the start, after `;`, and URL-encoded inside another
 *   URL), JSON members (`"access_token":"…"`), `Bearer`/`Basic` credentials
 *   and bare JWTs;
 * - exceptions in the context are replaced by their class and scrubbed
 *   message.
 */
class SensitiveDataProcessor implements ProcessorInterface
{
    private const MASK = '***MASKED***';

    /** Keys (normalized: lowercase, without `_`/`-`) whose values are always masked. */
    private const SENSITIVE_KEYS = [
        'clientsecret',
        'secret',
        'password',
        'token',
        'idtokenhint',
        'codeverifier',
        'code',
        'nonce',
        'sw6oidcnonce',
        'state',
        'authorization',
        'cookie',
        'setcookie',
        'jwt',
        'sessionkey',
        'apikey',
        'accesskey',
        'webhookurl',
        'healthalertwebhookurl',
    ];

    /** Normalized key suffixes that always mark a credential (accessToken, contextToken, xSecret, …). */
    private const SENSITIVE_KEY_SUFFIXES = ['token', 'secret', 'password', 'apikey', 'sessionkey'];

    private const PARAMETER_NAMES = 'state|nonce|sw6oidc_nonce|code|code_verifier|id_token_hint|id_token|access_token'
        . '|refresh_token|logout_token|token|client_secret|password|sw-context-token|context_token';

    /** @var list<array{string, string}> pattern => replacement */
    private const STRING_PATTERNS = [
        // name=value in a query string, form body or `;` list, also at the very start
        ['/((?:^|[?&#;\s])(?:' . self::PARAMETER_NAMES . ')=)[^&#;\s"\'<>]+/i', '$1' . self::MASK],
        // the same, URL-encoded inside another URL (`%3Fcode%3D…`, `%26state%3D…`)
        ['/((?:%3F|%26|%23)(?:' . self::PARAMETER_NAMES . ')%3D)(?:(?!%26|%23)[^&#\s"\'<>])+/i', '$1' . self::MASK],
        // JSON members: "access_token": "…"
        ['/("(?:' . self::PARAMETER_NAMES . '|clientSecret|accessToken|refreshToken|idToken|contextToken)"\s*:\s*")(?:[^"\\\\]|\\\\.)*"/i', '$1' . self::MASK . '"'],
        // Authorization header values
        ['/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/', '$1 ' . self::MASK],
        // bare JWTs (header.payload.signature)
        ['/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/', self::MASK],
    ];

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(
            message: $this->scrubString($record->message),
            context: $this->maskRecursively($record->context),
        );
    }

    /**
     * @param array<array-key, mixed> $context
     *
     * @return array<array-key, mixed>
     */
    private function maskRecursively(array $context): array
    {
        foreach ($context as $key => $value) {
            if (\is_string($key) && $this->isSensitiveKey($key) && $value !== null && $value !== '' && !\is_bool($value)) {
                $context[$key] = self::MASK;

                continue;
            }

            if (\is_array($value)) {
                $context[$key] = $this->maskRecursively($value);
            } elseif (\is_string($value)) {
                $context[$key] = $this->scrubString($value);
            } elseif ($value instanceof \Throwable) {
                // Exception messages can quote URLs or responses (e.g. an HTTP client error).
                $context[$key] = $value::class . ': ' . $this->scrubString($value->getMessage());
            }
        }

        return $context;
    }

    private function isSensitiveKey(string $key): bool
    {
        $normalized = str_replace(['_', '-'], '', strtolower($key));

        if (\in_array($normalized, self::SENSITIVE_KEYS, true)) {
            return true;
        }

        foreach (self::SENSITIVE_KEY_SUFFIXES as $suffix) {
            if (str_ends_with($normalized, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function scrubString(string $value): string
    {
        foreach (self::STRING_PATTERNS as [$pattern, $replacement]) {
            $value = (string) preg_replace($pattern, $replacement, $value);
        }

        return $value;
    }
}
