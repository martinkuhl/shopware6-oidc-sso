<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Jwt;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Verifies OIDC id_tokens and back-channel logout tokens: RS256/384/512,
 * PS256/384/512 or ES256/384/512 signature (R4-L3) against the provider's JWKS (cached, per-provider TTL, key
 * selected by kid/alg/use), plus exp/nbf/iat (with clock leeway), iss, aud,
 * azp and nonce checks.
 */
class JwtVerifier
{
    private const JWKS_FAILURE_TTL_SECONDS = 60;

    /** Tolerated clock difference between IdP and shop. */
    public const LEEWAY_SECONDS = 60;

    /** Logout tokens older than this are refused (replay window, N-L2). */
    public const LOGOUT_TOKEN_MAX_AGE_SECONDS = 300;

    /** Key-rotation refetch cooldown namespaces: logins vs. anonymous back-channel logout. */
    private const SCOPE_LOGIN = 'login';

    /** Longer `kid` headers are refused before any lookup (R3-M1). */
    private const MAX_KID_LENGTH = 256;
    private const SCOPE_LOGOUT = 'logout';

    /**
     * Signature algorithms the verifier accepts, with the key type (and EC
     * curve) a key must have for each. No `none`, no HMAC: the client secret
     * must never become a verification key.
     */
    public const SUPPORTED_ALGORITHMS = [
        'RS256' => ['RSA', null],
        'RS384' => ['RSA', null],
        'RS512' => ['RSA', null],
        'PS256' => ['RSA', null],
        'PS384' => ['RSA', null],
        'PS512' => ['RSA', null],
        'ES256' => ['EC', 'P-256'],
        'ES384' => ['EC', 'P-384'],
        'ES512' => ['EC', 'P-521'],
    ];

    /** OIDC Back-Channel Logout 1.0 §2.4: the `events` member identifying a logout token. */
    public const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheItemPoolInterface $cache,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @return array<string, mixed> the decoded JWT payload (claims)
     *
     * @throws InvalidJwtException
     */
    public function verify(
        string $jwt,
        string $jwksEndpoint,
        string $issuer,
        string $audience,
        string $expectedNonce,
        int $jwksCacheTtlSeconds,
        int $httpTimeoutSeconds,
    ): array {
        $payload = $this->verifySignedPayload($jwt, $jwksEndpoint, $jwksCacheTtlSeconds, $httpTimeoutSeconds, self::SCOPE_LOGIN);

        $this->assertClaims($payload, $issuer, $audience, $expectedNonce);

        if (!isset($payload['iat']) || !is_numeric($payload['iat'])) {
            throw new InvalidJwtException('JWT has no "iat" claim.');
        }

        return $payload;
    }

    /**
     * Verifies an OIDC Back-Channel Logout token (§2.6): same signature and
     * exp/nbf/iss/aud checks as an id_token, plus: `iat` present and recent,
     * `jti` present (REQUIRED by §2.4, used for replay protection), an
     * `events` object containing the back-channel-logout member, `sub`
     * and/or `sid` present, and **no** `nonce` (which is what keeps an
     * id_token from being replayed as a logout token).
     *
     * @return array<string, mixed>
     *
     * @throws InvalidJwtException
     */
    public function verifyLogoutToken(
        string $jwt,
        string $jwksEndpoint,
        string $issuer,
        string $audience,
        int $jwksCacheTtlSeconds,
        int $httpTimeoutSeconds,
        /** false while the caller is rate-limited: cached keys only, never a JWKS fetch (R3-M1) */
        bool $allowRefetch = true,
    ): array {
        $payload = $this->verifySignedPayload($jwt, $jwksEndpoint, $jwksCacheTtlSeconds, $httpTimeoutSeconds, self::SCOPE_LOGOUT, $allowRefetch);

        $this->assertStandardClaims($payload, $issuer, $audience);

        if (!isset($payload['iat']) || !is_numeric($payload['iat'])) {
            throw new InvalidJwtException('Logout token has no "iat" claim.');
        }

        if ((int) $payload['iat'] < time() - self::LOGOUT_TOKEN_MAX_AGE_SECONDS - self::LEEWAY_SECONDS) {
            throw new InvalidJwtException('Logout token is too old.');
        }

        if (!\is_string($payload['jti'] ?? null) || $payload['jti'] === '') {
            throw new InvalidJwtException('Logout token has no "jti" claim.');
        }

        $events = $payload['events'] ?? null;

        if (!\is_array($events) || !\array_key_exists(self::BACKCHANNEL_LOGOUT_EVENT, $events) || !\is_array($events[self::BACKCHANNEL_LOGOUT_EVENT])) {
            throw new InvalidJwtException('Logout token has no back-channel logout "events" member.');
        }

        if (\array_key_exists('nonce', $payload)) {
            throw new InvalidJwtException('Logout token must not contain a "nonce" claim.');
        }

        $hasSub = \is_string($payload['sub'] ?? null) && $payload['sub'] !== '';
        $hasSid = \is_string($payload['sid'] ?? null) && $payload['sid'] !== '';

        if (!$hasSub && !$hasSid) {
            throw new InvalidJwtException('Logout token contains neither "sub" nor "sid".');
        }

        return $payload;
    }

    /**
     * Reads a JWT payload **without** verifying it — only to learn which
     * provider (`iss`) must verify it. Never trust the result on its own.
     *
     * @return array<string, mixed>|null
     */
    public function decodeUnverified(string $jwt): ?array
    {
        return JwtPayloadReader::decode($jwt);
    }

    /**
     * Signature check with key selection: only keys of the right type
     * (RSA), usage (`use` absent or `sig`), algorithm (`alg` absent or the
     * token's) and — when the token names one — `kid` are tried.
     *
     * A forced JWKS refetch happens only when the token's `kid` is not in
     * the cached set (key rotation), at most once per cooldown window: per
     * endpoint and `kid` for logins, per endpoint only for back-channel
     * logout, whose tokens anyone can send with a fresh random `kid` (R3-M1).
     * A token signed with a *known* key that doesn't verify is simply forged
     * — it never costs a refetch, so an attacker can't use up the rotation
     * refetch (N-H2). Logout never refetches for tokens without a `kid`, and
     * a failing logout fetch never pauses logins (separate breakers).
     *
     * @param string $refreshScope self::SCOPE_LOGIN | self::SCOPE_LOGOUT
     *
     * @return array<string, mixed>
     *
     * @throws InvalidJwtException
     */
    private function verifySignedPayload(
        string $jwt,
        string $jwksEndpoint,
        int $jwksCacheTtlSeconds,
        int $httpTimeoutSeconds,
        string $refreshScope,
        bool $allowRefetch = true,
    ): array {
        $jws = $this->deserialize($jwt);
        $alg = $this->assertSupportedAlgorithm($jws);
        $signature = $jws->getSignature(0);
        $kid = $signature->hasProtectedHeaderParameter('kid') ? $signature->getProtectedHeaderParameter('kid') : null;
        $kid = \is_string($kid) && $kid !== '' ? $kid : null;

        // RFC 7515 §4.1.11: no header extensions are understood, so none may be critical (R4-L1).
        if ($signature->hasProtectedHeaderParameter('crit')) {
            throw new InvalidJwtException('JWT has a "crit" header; no critical header extensions are supported.');
        }

        if ($kid !== null && \strlen($kid) > self::MAX_KID_LENGTH) {
            throw new InvalidJwtException('JWT "kid" header is too long.');
        }

        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new RS256(), new RS384(), new RS512(), new PS256(), new PS384(), new PS512(), new ES256(), new ES384(), new ES512()]));

        $candidates = $this->candidateKeys($this->getJwks($jwksEndpoint, $jwksCacheTtlSeconds, $httpTimeoutSeconds, false, $refreshScope), $alg, $kid);
        $mayRefetch = $allowRefetch && ($kid !== null ? $candidates->count() === 0 : $refreshScope === self::SCOPE_LOGIN);

        if (($candidates->count() === 0 || !$jwsVerifier->verifyWithKeySet($jws, $candidates, 0)) && $mayRefetch) {
            $this->logger->info('sw6oidc: JWT key not in the cached JWKS; refetching once (key rotation).', ['kid' => $kid]);

            $refreshed = $this->refetchJwks($jwksEndpoint, $jwksCacheTtlSeconds, $httpTimeoutSeconds, $refreshScope, $kid);
            $candidates = $this->candidateKeys($refreshed, $alg, $kid);

            if ($candidates->count() === 0 || !$jwsVerifier->verifyWithKeySet($jws, $candidates, 0)) {
                throw new InvalidJwtException('JWT signature verification failed against the provider JWKS.');
            }
        } elseif ($candidates->count() === 0 || !$jwsVerifier->verifyWithKeySet($jws, $candidates, 0)) {
            throw new InvalidJwtException('JWT signature verification failed against the provider JWKS.');
        }

        $payload = json_decode($jws->getPayload() ?? '', true);

        if (!\is_array($payload)) {
            throw new InvalidJwtException('JWT payload is not a valid JSON object.');
        }

        return $payload;
    }

    private function candidateKeys(JWKSet $keys, string $alg, ?string $kid): JWKSet
    {
        $candidates = [];

        [$keyType, $curve] = self::SUPPORTED_ALGORITHMS[$alg];

        foreach ($keys->all() as $key) {
            if ($key->get('kty') !== $keyType || ($curve !== null && (!$key->has('crv') || $key->get('crv') !== $curve))) {
                continue;
            }

            if ($key->has('use') && $key->get('use') !== 'sig') {
                continue;
            }

            if ($key->has('alg') && $key->get('alg') !== $alg) {
                continue;
            }

            if ($kid !== null && (!$key->has('kid') || $key->get('kid') !== $kid)) {
                continue;
            }

            $candidates[] = $key;
        }

        return new JWKSet($candidates);
    }

    /**
     * @throws InvalidJwtException when the cooldown for this endpoint (and, for logins, kid) is active
     */
    private function refetchJwks(string $jwksEndpoint, int $ttlSeconds, int $httpTimeoutSeconds, string $scope, ?string $kid): JWKSet
    {
        // Logout tokens are anonymous: an attacker-chosen kid must not open a new window.
        $cooldownKid = $scope === self::SCOPE_LOGIN ? ($kid ?? '') : '';
        $cooldownItem = $this->cache->getItem(sprintf(
            'sw6oidc_jwks_refreshed_%s_%s',
            $scope,
            hash('sha256', $jwksEndpoint . "\0" . $cooldownKid),
        ));

        if ($cooldownItem->isHit()) {
            throw new InvalidJwtException('JWT signature verification failed against the provider JWKS.');
        }

        $cooldownItem->set(true);
        $cooldownItem->expiresAfter(self::JWKS_FAILURE_TTL_SECONDS);
        $this->cache->save($cooldownItem);

        return $this->getJwks($jwksEndpoint, $ttlSeconds, $httpTimeoutSeconds, true, $scope);
    }

    private function deserialize(string $jwt): \Jose\Component\Signature\JWS
    {
        try {
            return (new CompactSerializer())->unserialize($jwt);
        } catch (\Throwable $exception) {
            throw new InvalidJwtException('Malformed JWT: ' . $exception->getMessage(), $exception);
        }
    }

    private function assertSupportedAlgorithm(\Jose\Component\Signature\JWS $jws): string
    {
        $alg = $jws->getSignature(0)->getProtectedHeaderParameter('alg');

        if (!\is_string($alg) || !\array_key_exists($alg, self::SUPPORTED_ALGORITHMS)) {
            throw new InvalidJwtException(sprintf('Unsupported JWT signature algorithm "%s".', \is_scalar($alg) ? (string) $alg : ''));
        }

        return $alg;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function assertClaims(array $payload, string $issuer, string $audience, string $expectedNonce): void
    {
        $this->assertStandardClaims($payload, $issuer, $audience);

        // Always checked: there is no "skip the nonce" mode (R3-L7).
        if (($payload['nonce'] ?? null) !== $expectedNonce) {
            throw new InvalidJwtException('JWT nonce does not match the nonce sent in the authorization request.');
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function assertStandardClaims(array $payload, string $issuer, string $audience): void
    {
        $now = time();

        if (!isset($payload['exp']) || !is_numeric($payload['exp']) || $now >= (int) $payload['exp'] + self::LEEWAY_SECONDS) {
            throw new InvalidJwtException('JWT has expired.');
        }

        // A present but non-numeric time claim is invalid, never "0" (R4-L2).
        foreach (['nbf', 'iat'] as $timeClaim) {
            if (\array_key_exists($timeClaim, $payload) && !is_numeric($payload[$timeClaim])) {
                throw new InvalidJwtException(sprintf('JWT "%s" claim is not a number.', $timeClaim));
            }
        }

        if (isset($payload['nbf']) && $now + self::LEEWAY_SECONDS < (int) $payload['nbf']) {
            throw new InvalidJwtException('JWT is not yet valid.');
        }

        if (isset($payload['iat']) && $now + self::LEEWAY_SECONDS < (int) $payload['iat']) {
            throw new InvalidJwtException('JWT was issued in the future.');
        }

        if (($payload['iss'] ?? null) !== $issuer) {
            throw new InvalidJwtException('JWT issuer does not match the configured provider issuer.');
        }

        $aud = $payload['aud'] ?? null;
        $audienceMatches = \is_array($aud) ? \in_array($audience, $aud, true) : $aud === $audience;

        if (!$audienceMatches) {
            throw new InvalidJwtException("JWT audience does not match this provider's client id.");
        }

        // OIDC Core §3.1.3.7: with several audiences (or an azp at all), the
        // authorized party must be this client.
        $multipleAudiences = \is_array($aud) && \count($aud) > 1;

        if (($multipleAudiences || \array_key_exists('azp', $payload)) && ($payload['azp'] ?? null) !== $audience) {
            throw new InvalidJwtException('JWT authorized party (azp) is not this client.');
        }
    }

    /**
     * JWKS from cache, else fetched. A failed fetch trips a 60s circuit
     * breaker (flag in the same cache pool) so an unreachable IdP doesn't
     * cost a blocking HTTP timeout on every single login attempt.
     *
     * @throws InvalidJwtException
     */
    private function getJwks(string $jwksEndpoint, int $ttlSeconds, int $httpTimeoutSeconds, bool $forceRefresh, string $scope = self::SCOPE_LOGIN): JWKSet
    {
        $endpointHash = hash('sha256', $jwksEndpoint);
        $item = $this->cache->getItem('sw6oidc_jwks_' . $endpointHash);

        // Forced refetches are rate-limited by the caller (refetchJwks()).
        if (!$forceRefresh && $item->isHit() && \is_string($item->get())) {
            try {
                return JWKSet::createFromJson($item->get());
            } catch (\Throwable) {
                // Corrupted cache entry: fall through and re-fetch.
            }
        }

        // Per scope: a logout fetch an attacker made fail must not pause logins (R3-M1).
        $failKey = 'sw6oidc_jwks_fail_' . $scope . '_' . $endpointHash;

        if ($this->cache->getItem($failKey)->isHit()) {
            throw new InvalidJwtException('The provider JWKS endpoint is temporarily unavailable (recent fetch failed); try again shortly.');
        }

        try {
            $json = $this->httpClient->request('GET', $jwksEndpoint, ['timeout' => $httpTimeoutSeconds])->getContent();
            $jwkSet = JWKSet::createFromJson($json);

            if ($jwkSet->count() === 0) {
                throw new \RuntimeException('JWKS contains no keys.');
            }
        } catch (\Throwable $exception) {
            $failItem = $this->cache->getItem($failKey);
            $failItem->set(true);
            $failItem->expiresAfter(self::JWKS_FAILURE_TTL_SECONDS);
            $this->cache->save($failItem);

            $this->logger->warning('sw6oidc: JWKS fetch failed; pausing further fetches for this endpoint.', [
                'jwksEndpoint' => $jwksEndpoint,
                'pauseSeconds' => self::JWKS_FAILURE_TTL_SECONDS,
                'exceptionClass' => $exception::class,
            ]);

            throw new InvalidJwtException('Could not fetch the provider JWKS.', $exception);
        }

        $item->set($json);
        $item->expiresAfter($ttlSeconds);
        $this->cache->save($item);

        return $jwkSet;
    }
}
