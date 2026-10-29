<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

/**
 * A minimal ES256 WebAuthn authenticator for unit tests: produces genuine
 * "none"-attestation registration responses and signed assertion responses,
 * so the webauthn-lib validators run for real instead of being mocked.
 */
final class SoftwareAuthenticator
{
    public readonly string $credentialId;

    private \OpenSSLAsymmetricKey $key;

    private int $counter = 0;

    /**
     * @param string|null $rpIdOverride  sign for this RP ID instead of the origin's host (relay attacks)
     * @param bool        $userVerified  whether the authenticator reports user verification (PIN/biometrics)
     */
    public function __construct(
        private readonly string $origin = 'https://shop.example',
        private readonly ?string $rpIdOverride = null,
        private bool $userVerified = true,
    ) {
        $key = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        \assert($key instanceof \OpenSSLAsymmetricKey);
        $this->key = $key;
        $this->credentialId = random_bytes(16);
    }

    public function rpId(): string
    {
        return $this->rpIdOverride ?? (string) parse_url($this->origin, \PHP_URL_HOST);
    }

    public function setUserVerified(bool $userVerified): void
    {
        $this->userVerified = $userVerified;
    }

    /**
     * Simulates a cloned authenticator whose counter lags behind.
     */
    public function rewindCounter(int $counter): void
    {
        $this->counter = $counter;
    }

    /**
     * @param array<string, mixed> $options creation options as sent to the browser
     */
    public function register(array $options): string
    {
        $details = openssl_pkey_get_details($this->key);
        \assert(\is_array($details));

        // OpenSSL returns the coordinates as minimal big-endian integers; COSE
        // requires the full 32 bytes (a leading zero byte made ~1 in 128 runs fail).
        $x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        $coseKey = self::cbor([1 => 2, 3 => -7, -1 => 1, -2 => new CborBytes($x), -3 => new CborBytes($y)]);
        $authData = hash('sha256', $this->rpId(), true)
            . \chr($this->userVerified ? 0x45 : 0x41) // UP | (UV) | AT
            . pack('N', $this->counter)
            . str_repeat("\0", 16) // aaguid
            . pack('n', \strlen($this->credentialId)) . $this->credentialId
            . $coseKey;

        $attestationObject = self::cbor(['fmt' => 'none', 'attStmt' => [], 'authData' => new CborBytes($authData)]);

        return $this->credentialJson([
            'clientDataJSON' => self::b64($this->clientData('webauthn.create', (string) $options['challenge'])),
            'attestationObject' => self::b64($attestationObject),
        ]);
    }

    /**
     * @param array<string, mixed> $options request options as sent to the browser
     */
    public function assert(array $options, string $userHandle): string
    {
        ++$this->counter;

        $authData = hash('sha256', $this->rpId(), true) . \chr($this->userVerified ? 0x05 : 0x01) . pack('N', $this->counter);
        $clientData = $this->clientData('webauthn.get', (string) $options['challenge']);
        openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, \OPENSSL_ALGO_SHA256);

        return $this->credentialJson([
            'clientDataJSON' => self::b64($clientData),
            'authenticatorData' => self::b64($authData),
            'signature' => self::b64($signature),
            'userHandle' => self::b64($userHandle),
        ]);
    }

    public static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function unb64(string $b64url): string
    {
        return (string) base64_decode(strtr($b64url, '-_', '+/'), true);
    }

    /**
     * @param array<string, string> $response
     */
    private function credentialJson(array $response): string
    {
        $id = self::b64($this->credentialId);

        return json_encode(['id' => $id, 'rawId' => $id, 'type' => 'public-key', 'response' => $response], \JSON_THROW_ON_ERROR);
    }

    private function clientData(string $type, string $challenge): string
    {
        return json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $this->origin, 'crossOrigin' => false], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
    }

    private static function cbor(mixed $value): string
    {
        return match (true) {
            $value instanceof CborBytes => self::cborHead(2, \strlen($value->bytes)) . $value->bytes,
            \is_string($value) => self::cborHead(3, \strlen($value)) . $value,
            \is_int($value) && $value >= 0 => self::cborHead(0, $value),
            \is_int($value) => self::cborHead(1, -1 - $value),
            \is_array($value) => self::cborHead(5, \count($value)) . implode('', array_map(
                static fn (int|string $k, mixed $v): string => self::cbor($k) . self::cbor($v),
                array_keys($value),
                $value,
            )),
            default => throw new \LogicException('Unsupported CBOR value'),
        };
    }

    private static function cborHead(int $major, int $length): string
    {
        return match (true) {
            $length < 24 => \chr(($major << 5) | $length),
            $length < 0x100 => \chr(($major << 5) | 24) . \chr($length),
            default => \chr(($major << 5) | 25) . pack('n', $length),
        };
    }
}
