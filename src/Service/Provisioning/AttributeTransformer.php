<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AttributeTransformFailedException;
use Psr\Log\LoggerInterface;

/**
 * Per-attribute value transforms (sw6oidc_attribute_mapping.transform_function
 * + transform_params), applied to the claim value AttributeMapper read before
 * it's mapped onto a Shopware field:
 *
 *  - concat        {claims: string[], separator?: string (default " ")}
 *                  the value followed by the listed claims' values, joined;
 *                  empty/missing parts are skipped
 *  - split         {separator: string, index: int (negative = from the end)}
 *                  one segment of the value; out of range yields null
 *  - prefix        {value: string}
 *  - regex_replace {pattern: string, replacement?: string}
 *                  input and pattern capped at 4096 bytes
 *
 * Lenient by default: an unknown function, invalid params or a failing regex
 * logs a warning and passes the raw value through unchanged, so a
 * misconfigured mapping degrades to "no transform". For identity attributes
 * (email, username) the strict mode throws AttributeTransformFailedException
 * instead, since the raw value would be used for account linking (N-L7).
 */
class AttributeTransformer
{
    public const CONCAT = 'concat';
    public const SPLIT = 'split';
    public const PREFIX = 'prefix';
    public const REGEX_REPLACE = 'regex_replace';

    public const FUNCTIONS = [self::CONCAT, self::SPLIT, self::PREFIX, self::REGEX_REPLACE];

    public const MAX_REGEX_BYTES = 4096;

    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    /**
     * @param array<string, mixed> $params
     * @param array<string, mixed> $flattenedClaims
     * @param bool                 $strict for identity attributes (email, username): a failed transform
     *                                     fails the login instead of passing the raw IdP value through
     *
     * @throws AttributeTransformFailedException in strict mode
     */
    public function apply(?string $function, array $params, ?string $value, array $flattenedClaims, bool $strict = false): ?string
    {
        if ($function === null || $function === '') {
            return $value;
        }

        try {
            $result = match ($function) {
                self::CONCAT => $this->concat($params, $value, $flattenedClaims),
                self::SPLIT => $this->split($params, $value),
                self::PREFIX => $value === null ? null : $this->stringParam($params, 'value') . $value,
                self::REGEX_REPLACE => $this->regexReplace($params, $value),
                default => throw new \InvalidArgumentException(sprintf('Unknown transform function "%s".', $function)),
            };
        } catch (\Throwable $exception) {
            if ($strict) {
                $this->logger->warning('sw6oidc: transform of an identity attribute failed; refusing the login.', [
                    'function' => $function,
                    'exception' => $exception->getMessage(),
                ]);

                throw new AttributeTransformFailedException(sprintf('The "%s" transform failed.', $function), $exception);
            }

            $this->logger->warning('sw6oidc: attribute transform failed; using the untransformed value.', [
                'function' => $function,
                'exception' => $exception->getMessage(),
            ]);

            return $value;
        }

        return $result === null || trim($result) === '' ? null : trim($result);
    }

    /**
     * @param array<string, mixed> $params
     * @param array<string, mixed> $flattenedClaims
     */
    private function concat(array $params, ?string $value, array $flattenedClaims): ?string
    {
        $claims = $params['claims'] ?? [];

        if (!\is_array($claims)) {
            throw new \InvalidArgumentException('concat: "claims" must be a list of claim keys.');
        }

        $parts = [$value];

        foreach ($claims as $claimKey) {
            $claimValue = \is_string($claimKey) ? ($flattenedClaims[$claimKey] ?? null) : null;
            $parts[] = \is_scalar($claimValue) ? trim((string) $claimValue) : null;
        }

        $parts = array_filter($parts, static fn (?string $part): bool => $part !== null && $part !== '');

        return $parts === [] ? null : implode($this->stringParam($params, 'separator', ' '), $parts);
    }

    /**
     * @param array<string, mixed> $params
     */
    private function split(array $params, ?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $separator = $this->stringParam($params, 'separator');

        if ($separator === '') {
            throw new \InvalidArgumentException('split: "separator" must not be empty.');
        }

        $index = $params['index'] ?? 0;

        if (!\is_int($index) && (!\is_string($index) || !preg_match('/^-?\d+$/', $index))) {
            throw new \InvalidArgumentException('split: "index" must be an integer.');
        }

        $segments = explode($separator, $value);
        $index = (int) $index;

        if ($index < 0) {
            $index += \count($segments);
        }

        return $index >= 0 ? ($segments[$index] ?? null) : null;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function regexReplace(array $params, ?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $pattern = $this->stringParam($params, 'pattern');

        if ($pattern === '' || \strlen($pattern) > self::MAX_REGEX_BYTES || \strlen($value) > self::MAX_REGEX_BYTES) {
            throw new \InvalidArgumentException('regex_replace: pattern missing, or pattern/value exceeds 4096 bytes.');
        }

        $result = @preg_replace($pattern, $this->stringParam($params, 'replacement'), $value);

        if ($result === null || preg_last_error() !== \PREG_NO_ERROR) {
            throw new \InvalidArgumentException('regex_replace: invalid pattern or regex error (' . preg_last_error_msg() . ').');
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function stringParam(array $params, string $key, string $default = ''): string
    {
        $value = $params[$key] ?? $default;

        if (!\is_scalar($value)) {
            throw new \InvalidArgumentException(sprintf('Transform parameter "%s" must be a string.', $key));
        }

        return (string) $value;
    }
}
