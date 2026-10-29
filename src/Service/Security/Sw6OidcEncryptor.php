<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Encrypts secrets and security state at rest, keyed from APP_SECRET.
 *
 * Format v2 ("sw6oidc_v2:" . base64(nonce . ciphertext)): XChaCha20-Poly1305
 * (AEAD) with a key derived per *purpose* (keyed BLAKE2b over a master key)
 * and the purpose as associated data — so an envelope written for one field
 * or table can't be swapped into another and still decrypt (N-L4). Callers
 * name the purpose, e.g. "sw6oidc_provider.client_secret" or
 * "one_time_token".
 *
 * Format v1 ("sw6oidc_v1:", secretbox, one key for everything) is still read;
 * Migration1790800010ReencryptSecrets upgrades stored provider secrets.
 *
 * decrypt() never throws: an unprefixed value is legacy plaintext and is
 * returned as-is; an envelope that doesn't decrypt (APP_SECRET rotated,
 * corrupted, wrong purpose) is also returned as-is and logged, so entity
 * hydration never breaks. Code about to *use* a value calls decryptOrNull()
 * or isEnvelope() instead, so ciphertext is never mistaken for the secret.
 *
 * Constructible from a plain string (no container) so a Migration can use it.
 */
class Sw6OidcEncryptor implements ResetInterface
{
    /** @var array<string, true> undecryptable values already reported in this request */
    private array $reported = [];

    public const PREFIX = 'sw6oidc_v2:';
    public const LEGACY_PREFIX = 'sw6oidc_v1:';

    public const DEFAULT_PURPOSE = 'default';

    private readonly string $masterKey;

    private readonly string $legacyKey;

    /** @var array<string, string> */
    private array $purposeKeys = [];

    public function __construct(
        #[\SensitiveParameter]
        string $appSecret,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if ($appSecret === '') {
            throw new \InvalidArgumentException('APP_SECRET is empty; cannot derive the sw6oidc encryption key.');
        }

        $this->masterKey = sodium_crypto_generichash($appSecret . "\0sw6oidc/master/v2", '', \SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
        $this->legacyKey = sodium_crypto_generichash($appSecret . "\0sw6oidc/client_secret/v1", '', \SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * Whether a (hydrated) value is still an envelope, i.e. could not be
     * decrypted — such a value must never be used as the secret itself.
     */
    public static function isEnvelope(string $value): bool
    {
        return str_starts_with($value, self::PREFIX) || str_starts_with($value, self::LEGACY_PREFIX);
    }

    public function encrypt(#[\SensitiveParameter] string $plaintext, string $purpose = self::DEFAULT_PURPOSE): string
    {
        $nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $purpose, $nonce, $this->purposeKey($purpose));

        return self::PREFIX . base64_encode($nonce . $ciphertext);
    }

    public function decrypt(string $value, string $purpose = self::DEFAULT_PURPOSE): string
    {
        if (!$this->isEncrypted($value)) {
            return $value;
        }

        $plaintext = $this->tryDecrypt($value, $purpose);

        if ($plaintext === null) {
            $this->reportUndecryptable($value, $purpose);

            return $value;
        }

        return $plaintext;
    }

    /**
     * Hydrating a provider decrypts every envelope it has, on every login
     * page and admin listing: an undecryptable one is reported once per
     * request, not on each of those reads (R3-L42).
     */
    private function reportUndecryptable(string $value, string $purpose): void
    {
        $key = $purpose . "\0" . hash('sha256', $value);

        if (isset($this->reported[$key])) {
            return;
        }

        $this->reported[$key] = true;

        $this->logger?->error('sw6oidc: an encrypted value could not be decrypted (was APP_SECRET changed?). Re-enter the secret to fix this.', [
            'purpose' => $purpose,
        ]);
    }

    public function reset(): void
    {
        $this->reported = [];
    }

    /**
     * Like decrypt(), but a value that can't be decrypted yields null instead
     * of the envelope (N-L5). Unencrypted legacy values pass through.
     */
    public function decryptOrNull(string $value, string $purpose = self::DEFAULT_PURPOSE): ?string
    {
        if (!$this->isEncrypted($value)) {
            return $value;
        }

        return $this->tryDecrypt($value, $purpose);
    }

    public function isEncrypted(string $value): bool
    {
        return self::isEnvelope($value);
    }

    public function canDecrypt(string $value, string $purpose = self::DEFAULT_PURPOSE): bool
    {
        return $this->isEncrypted($value) && $this->tryDecrypt($value, $purpose) !== null;
    }

    public function isLegacy(string $value): bool
    {
        return str_starts_with($value, self::LEGACY_PREFIX);
    }

    private function tryDecrypt(string $value, string $purpose): ?string
    {
        if ($this->isLegacy($value)) {
            return $this->tryDecryptLegacy($value);
        }

        $raw = base64_decode(substr($value, \strlen(self::PREFIX)), true);
        $nonceLength = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if ($raw === false || \strlen($raw) < $nonceLength + \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            return null;
        }

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($raw, $nonceLength),
            $purpose,
            substr($raw, 0, $nonceLength),
            $this->purposeKey($purpose),
        );

        return $plaintext === false ? null : $plaintext;
    }

    private function tryDecryptLegacy(string $value): ?string
    {
        $raw = base64_decode(substr($value, \strlen(self::LEGACY_PREFIX)), true);

        if ($raw === false || \strlen($raw) < \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + \SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            return null;
        }

        $plaintext = sodium_crypto_secretbox_open(
            substr($raw, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->legacyKey,
        );

        return $plaintext === false ? null : $plaintext;
    }

    private function purposeKey(string $purpose): string
    {
        return $this->purposeKeys[$purpose] ??= sodium_crypto_generichash(
            'sw6oidc/kdf/' . $purpose,
            $this->masterKey,
            \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
        );
    }
}
