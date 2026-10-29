<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;

/**
 * Fetches a provider's `.well-known/openid-configuration` discovery document and
 * maps it to our provider entity's endpoint field names — used by the admin
 * Provider save flow to auto-populate endpoints.
 */
class OidcDiscoveryService
{
    private const DEFAULT_TIMEOUT_SECONDS = 10;

    public function __construct(private readonly OidcHttpClient $httpClient)
    {
    }

    /**
     * @return array{
     *     authorizeEndpoint?: string,
     *     accessTokenEndpoint?: string,
     *     userInfoEndpoint?: string,
     *     endSessionEndpoint?: string,
     *     revocationEndpoint?: string,
     *     jwksEndpoint?: string,
     *     issuer?: string,
     *     idTokenSigningAlgValuesSupported?: list<string>,
     * }
     */
    public function discover(string $wellKnownConfigUrl, int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS): array
    {
        $document = $this->httpClient->getJson($wellKnownConfigUrl, $timeoutSeconds);

        $map = [
            'authorization_endpoint' => 'authorizeEndpoint',
            'token_endpoint' => 'accessTokenEndpoint',
            'userinfo_endpoint' => 'userInfoEndpoint',
            'end_session_endpoint' => 'endSessionEndpoint',
            'revocation_endpoint' => 'revocationEndpoint',
            'jwks_uri' => 'jwksEndpoint',
            'issuer' => 'issuer',
        ];

        $result = [];

        foreach ($map as $documentKey => $fieldName) {
            if (isset($document[$documentKey]) && \is_string($document[$documentKey])) {
                $result[$fieldName] = $document[$documentKey];
            }
        }

        $algorithms = $document['id_token_signing_alg_values_supported'] ?? null;

        if (\is_array($algorithms)) {
            $result['idTokenSigningAlgValuesSupported'] = array_values(array_filter($algorithms, is_string(...)));
        }

        return $result;
    }

    /**
     * A warning when the IdP advertises id_token signing algorithms and
     * none of them can be verified here — such a provider would pass every
     * configuration check and then fail at the first login (R4-L3).
     *
     * @param list<string>|null $advertised `id_token_signing_alg_values_supported`, null when not advertised
     */
    public static function unsupportedSigningAlgorithmsWarning(?array $advertised): ?string
    {
        if ($advertised === null || $advertised === []) {
            return null;
        }

        $supported = array_keys(JwtVerifier::SUPPORTED_ALGORITHMS);

        if (array_intersect($advertised, $supported) !== []) {
            return null;
        }

        return sprintf(
            'The provider signs ID tokens only with %s, which this plugin cannot verify (supported: %s).',
            implode(', ', $advertised),
            implode(', ', $supported),
        );
    }
}
