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
     *     claimsParameterSupported: bool,
     *     tokenEndpointAuthMethodsSupported?: list<string>,
     *     revocationEndpointAuthMethodsSupported?: list<string>,
     *     codeChallengeMethodsSupported?: list<string>,
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

        // OIDC Discovery §3: absent means false.
        $result['claimsParameterSupported'] = ($document['claims_parameter_supported'] ?? false) === true;

        $lists = [
            'id_token_signing_alg_values_supported' => 'idTokenSigningAlgValuesSupported',
            // What the IdP accepts, so the provider page can preselect it and
            // the connection test can flag a mismatch.
            'token_endpoint_auth_methods_supported' => 'tokenEndpointAuthMethodsSupported',
            'revocation_endpoint_auth_methods_supported' => 'revocationEndpointAuthMethodsSupported',
            'code_challenge_methods_supported' => 'codeChallengeMethodsSupported',
        ];

        foreach ($lists as $documentKey => $fieldName) {
            if (\is_array($document[$documentKey] ?? null)) {
                $result[$fieldName] = array_values(array_filter($document[$documentKey], is_string(...)));
            }
        }

        return $result;
    }

    /**
     * Where the configuration contradicts what discovery advertises: the
     * issuer must match exactly (OIDC Discovery §4.3 — a trailing slash
     * fails every login), and the client authentication and PKCE methods
     * should be ones the IdP supports.
     *
     * @param array<string, mixed>   $discovered discover()'s result
     * @param array<string, ?string> $configured issuer, tokenEndpointAuthMethod, revocationEndpointAuthMethod, pkceFlow
     *
     * @return array{errors: list<string>, warnings: list<string>}
     */
    public static function capabilityMismatches(array $discovered, array $configured): array
    {
        $errors = [];
        $warnings = [];

        $issuer = $configured['issuer'] ?? null;

        if ($issuer !== null && $issuer !== '' && \is_string($discovered['issuer'] ?? null) && $discovered['issuer'] !== $issuer) {
            $errors[] = sprintf('The configured issuer "%s" differs from the discovered one "%s"; every ID token would be refused.', $issuer, $discovered['issuer']);
        }

        foreach (
            [
            'tokenEndpointAuthMethod' => ['tokenEndpointAuthMethodsSupported', 'token endpoint'],
            'revocationEndpointAuthMethod' => ['revocationEndpointAuthMethodsSupported', 'revocation endpoint'],
            'pkceFlow' => ['codeChallengeMethodsSupported', 'PKCE'],
            ] as $setting => [$listKey, $label]
        ) {
            $value = $configured[$setting] ?? null;
            $supported = $discovered[$listKey] ?? null;

            if ($value !== null && \is_array($supported) && $supported !== [] && !\in_array($value, $supported, true)) {
                $warnings[] = sprintf('The %s method "%s" is not among the ones the IdP advertises (%s).', $label, $value, implode(', ', $supported));
            }
        }

        if (($configured['pkceFlow'] ?? null) === 'plain' && \in_array('S256', (array) ($discovered['codeChallengeMethodsSupported'] ?? []), true)) {
            $warnings[] = 'PKCE uses "plain" although the IdP supports S256; switch to S256.';
        }

        return ['errors' => $errors, 'warnings' => $warnings];
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
