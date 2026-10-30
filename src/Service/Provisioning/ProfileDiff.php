<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

/**
 * Helpers both provisioning services share, so customers and admins follow
 * the same rules (R3-L29, R8-L10).
 */
final class ProfileDiff
{
    private const PLACEHOLDER = '-';

    /**
     * The payload without the fields whose value is already stored: most
     * logins change nothing, and then nothing is written (no `*.written`
     * events, R3-L29). Dates compare by day, ids case-insensitively.
     *
     * @param array<string, mixed> $payload `id` is always kept
     * @param array<string, mixed> $current the stored values, by field name
     *
     * @return array<string, mixed>
     */
    public static function withoutUnchanged(array $payload, array $current): array
    {
        foreach ($payload as $field => $value) {
            if ($field === 'id' || !\array_key_exists($field, $current)) {
                continue;
            }

            $stored = $current[$field];
            $same = match (true) {
                $value instanceof \DateTimeInterface, $stored instanceof \DateTimeInterface => self::dateOf($value) === self::dateOf($stored),
                str_ends_with($field, 'Id') => \is_string($value) && \is_string($stored) && strtolower($value) === strtolower($stored),
                default => $value === $stored,
            };

            if ($same) {
                unset($payload[$field]);
            }
        }

        return $payload;
    }

    /**
     * Never the email address as a name (L9): it would end up on invoices
     * and in mails. The local part is a readable, editable stand-in.
     */
    public static function fallbackFirstName(MappedProfile $profile): string
    {
        if ($profile->firstName !== null) {
            return $profile->firstName;
        }

        $localPart = trim(explode('@', $profile->email)[0]);

        return $localPart !== '' ? mb_substr($localPart, 0, MappedProfile::MAX_NAME_LENGTH) : self::PLACEHOLDER;
    }

    private static function dateOf(mixed $value): mixed
    {
        return $value instanceof \DateTimeInterface ? $value->format('Y-m-d') : $value;
    }
}
