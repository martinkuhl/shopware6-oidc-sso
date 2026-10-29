<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Oidc\Exception\ClaimsTooComplexException;

/**
 * Flattens nested OIDC claim responses into dot-notation keys and normalizes
 * IdP-specific quirks, in particular Zitadel's (base64-encoded claims,
 * nested role objects).
 */
class ClaimsNormalizer
{
    private const MAX_RECURSION_DEPTH = 5;
    private const MAX_FLATTENED_KEYS = 2000;

    /**
     * @param array<string, mixed> $claims
     * @param list<string>         $base64Claims claim names whose values are base64-decoded ("*" = all, M10)
     *
     * @return array<string, mixed> dot-notation flattened claims
     *
     * @throws ClaimsTooComplexException
     */
    public function flatten(array $claims, array $base64Claims = []): array
    {
        $flattened = [];
        $this->flattenRecursive($claims, '', 0, $base64Claims, $flattened);

        return $flattened;
    }

    /**
     * Whether a (flattened) claim key is covered by the base64 list: the
     * name itself, anything nested under it, or "*".
     *
     * @param list<string> $base64Claims
     */
    public function isBase64Claim(string $key, array $base64Claims): bool
    {
        foreach ($base64Claims as $claim) {
            if ($claim === '*' || $key === $claim || str_starts_with($key, $claim . '.')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Decodes the normalized group names when the group claim is listed, so
     * groups and the flattened claims (access-control rules) agree.
     *
     * @param list<string> $groups
     * @param list<string> $base64Claims
     *
     * @return list<string>
     */
    public function decodeGroups(array $groups, string $groupAttribute, array $base64Claims): array
    {
        if (!$this->isBase64Claim($groupAttribute, $base64Claims)) {
            return $groups;
        }

        return array_map(fn (string $group): string => (string) $this->decode($group), $groups);
    }

    /**
     * @param array<mixed>         $claims
     * @param list<string>         $base64Claims
     * @param array<string, mixed> $target
     */
    private function flattenRecursive(array $claims, string $prefix, int $depth, array $base64Claims, array &$target): void
    {
        if ($depth > self::MAX_RECURSION_DEPTH) {
            return;
        }

        // The member names of an object-shaped top-level claim (Zitadel roles)
        // are decoded like decodeGroups() decodes them, so group mapping and
        // access-control rules see the same names (R3-L6).
        $decodeKeys = $depth === 1 && $this->isBase64Claim($prefix, $base64Claims);

        foreach ($claims as $key => $value) {
            if ($decodeKeys && \is_string($key)) {
                $key = (string) $this->decode($key);
            }

            $flatKey = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (\count($target) >= self::MAX_FLATTENED_KEYS) {
                throw new ClaimsTooComplexException('OIDC claims response is too large or deeply nested to process safely.');
            }

            if (\is_array($value)) {
                $this->flattenRecursive($value, $flatKey, $depth + 1, $base64Claims, $target);

                continue;
            }

            $target[$flatKey] = $this->isBase64Claim($flatKey, $base64Claims) ? $this->decode($value) : $value;
        }
    }

    private function decode(mixed $value): mixed
    {
        if (!\is_string($value) || $value === '') {
            return $value;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false || !mb_check_encoding($decoded, 'UTF-8')) {
            return $value;
        }

        return $decoded;
    }

    /**
     * Normalizes the group/role claim into a flat list of group name strings.
     * Handles three shapes seen across real IdPs:
     *  - a single string ("Engineering")
     *  - a flat array (["Engineering", "Developers"])
     *  - Zitadel's nested role-object shape ({"Engineering": {"orgId": "..."}}),
     *    where the parent keys are the group names.
     *
     * @return list<string>
     */
    public function normalizeGroups(mixed $groupsClaim): array
    {
        if (\is_string($groupsClaim)) {
            return $groupsClaim === '' ? [] : [$groupsClaim];
        }

        if (!\is_array($groupsClaim)) {
            return [];
        }

        // Note: a Zitadel role object whose *only* key is "0" ({"0": {...}})
        // decodes to the same PHP array as a JSON list ([{...}]) and is
        // therefore treated as a list — indistinguishable after json_decode().
        $isList = array_is_list($groupsClaim);

        if ($isList) {
            // Explicit callback: a bare array_filter() would also drop a group
            // literally named "0". Integer ids (some IdPs) are kept as strings.
            return array_values(array_filter(
                array_map(
                    static fn (mixed $item): ?string => \is_string($item) || \is_int($item) ? (string) $item : null,
                    $groupsClaim,
                ),
                static fn (?string $group): bool => $group !== null && $group !== '',
            ));
        }

        // Associative: Zitadel-style nested role object — parent keys are the groups.
        return array_map(strval(...), array_keys($groupsClaim));
    }
}
