<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;

/**
 * The fast, synchronous "Test Connection" check: no real login round trip,
 * just reachability/completeness checks against whatever configuration is
 * currently in the admin's form (saved or not) — well-known URL parses,
 * required endpoints are present, client credentials are filled in, and the
 * JWKS endpoint returns usable keys. Never persists anything.
 */
class OidcConnectionTestService
{
    private const REQUIRED_ENDPOINTS = [
        'authorizeEndpoint' => 'authorize',
        'accessTokenEndpoint' => 'token',
        'jwksEndpoint' => 'jwks',
    ];

    public function __construct(
        private readonly OidcHttpClient $httpClient,
        private readonly OidcDiscoveryService $discoveryService,
        private readonly SsrfUrlValidator $urlValidator,
    ) {
    }

    /**
     * @param array{
     *     wellKnownConfigUrl?: string|null,
     *     authorizeEndpoint?: string|null,
     *     accessTokenEndpoint?: string|null,
     *     userInfoEndpoint?: string|null,
     *     jwksEndpoint?: string|null,
     *     endSessionEndpoint?: string|null,
     *     revocationEndpoint?: string|null,
     *     issuer?: string|null,
     *     clientId?: string|null,
     *     hasClientSecret?: bool,
     *     publicClient?: bool,
     *     httpTimeout?: int,
     * } $config
     *
     * @return array{overallStatus: string, checks: array<int, array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}>}
     */
    public function test(array $config): array
    {
        $timeout = $config['httpTimeout'] ?? 10;

        $endpoints = [
            'authorizeEndpoint' => $this->nullIfEmpty($config['authorizeEndpoint'] ?? null),
            'accessTokenEndpoint' => $this->nullIfEmpty($config['accessTokenEndpoint'] ?? null),
            'userInfoEndpoint' => $this->nullIfEmpty($config['userInfoEndpoint'] ?? null),
            'jwksEndpoint' => $this->nullIfEmpty($config['jwksEndpoint'] ?? null),
            'endSessionEndpoint' => $this->nullIfEmpty($config['endSessionEndpoint'] ?? null),
            'revocationEndpoint' => $this->nullIfEmpty($config['revocationEndpoint'] ?? null),
            'issuer' => $this->nullIfEmpty($config['issuer'] ?? null),
        ];

        $checks = [];

        $wellKnownUrl = $this->nullIfEmpty($config['wellKnownConfigUrl'] ?? null);

        if ($wellKnownUrl !== null) {
            $checks[] = $this->checkWellKnown($wellKnownUrl, (int) $timeout, $endpoints);
        }

        $checks[] = $this->checkRequiredEndpoints($endpoints);
        $checks[] = $this->checkClientCredentials($config);
        $checks[] = $this->checkJwks($endpoints['jwksEndpoint'], (int) $timeout);

        return ['overallStatus' => $this->overallStatus($checks), 'checks' => $checks];
    }

    /**
     * @param array<string, string|null> $endpoints
     *
     * @return array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}
     */
    private function checkWellKnown(string $url, int $timeout, array &$endpoints): array
    {
        $violation = $this->urlValidator->validate($url);

        if ($violation['blocked']) {
            return ['id' => 'well_known_reachable', 'status' => 'fail', 'detail' => implode(' ', $violation['warnings'])];
        }

        try {
            $document = $this->discoveryService->discover($url, $timeout);
        } catch (OidcHttpException $exception) {
            return ['id' => 'well_known_reachable', 'status' => 'fail', 'detail' => $exception->getMessage()];
        }

        $algorithmWarning = OidcDiscoveryService::unsupportedSigningAlgorithmsWarning($document['idTokenSigningAlgValuesSupported'] ?? null);
        unset($document['idTokenSigningAlgValuesSupported']);

        // Fill in any endpoint the admin hasn't manually overridden, so the
        // downstream checks (required-endpoints, JWKS) see discovered values too.
        foreach ($document as $key => $value) {
            $endpoints[$key] ??= $value;
        }

        if ($algorithmWarning !== null) {
            return ['id' => 'well_known_reachable', 'status' => 'fail', 'detail' => $algorithmWarning];
        }

        if ($violation['warnings'] !== []) {
            return ['id' => 'well_known_reachable', 'status' => 'warning', 'detail' => implode(' ', $violation['warnings'])];
        }

        return [
            'id' => 'well_known_reachable',
            'status' => 'pass',
            'detail' => 'Well-known configuration document fetched and parsed successfully.',
            'messageKey' => 'wellKnownReachablePass',
        ];
    }

    /**
     * @param array<string, string|null> $endpoints
     *
     * @return array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}
     */
    private function checkRequiredEndpoints(array $endpoints): array
    {
        $missing = [];

        foreach (self::REQUIRED_ENDPOINTS as $field => $label) {
            if (($endpoints[$field] ?? null) === null) {
                $missing[] = $label;
            }
        }

        if ($missing !== []) {
            return [
                'id' => 'required_endpoints_present',
                'status' => 'fail',
                'detail' => 'Missing required endpoint(s): ' . implode(', ', $missing) . '.',
                'messageKey' => 'requiredEndpointsMissing',
                'messageParams' => ['endpoints' => implode(', ', $missing)],
            ];
        }

        return [
            'id' => 'required_endpoints_present',
            'status' => 'pass',
            'detail' => 'Authorize, token, and JWKS endpoints are all present.',
            'messageKey' => 'requiredEndpointsPass',
        ];
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}
     */
    private function checkClientCredentials(array $config): array
    {
        $clientId = trim((string) ($config['clientId'] ?? ''));
        // Only whether a secret exists: the test never needs its value (R3-L44).
        $hasClientSecret = (bool) ($config['hasClientSecret'] ?? false);
        $publicClient = (bool) ($config['publicClient'] ?? false);

        if ($clientId === '') {
            return ['id' => 'client_credentials_present', 'status' => 'fail', 'detail' => 'Client ID is not set.', 'messageKey' => 'clientIdMissing'];
        }

        if (!$publicClient && !$hasClientSecret) {
            return [
                'id' => 'client_credentials_present',
                'status' => 'fail',
                'detail' => 'Client secret is not set (required unless this is a public client).',
                'messageKey' => 'clientSecretMissing',
            ];
        }

        $detail = $publicClient ? 'Client ID is set.' : 'Client ID and client secret are set.';
        $messageKey = $publicClient ? 'clientIdPass' : 'clientCredentialsPass';

        return ['id' => 'client_credentials_present', 'status' => 'pass', 'detail' => $detail, 'messageKey' => $messageKey];
    }

    /**
     * @return array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}
     */
    private function checkJwks(?string $jwksEndpoint, int $timeout): array
    {
        if ($jwksEndpoint === null) {
            return [
                'id' => 'jwks_reachable',
                'status' => 'warning',
                'detail' => 'No JWKS endpoint configured; ID tokens cannot be signature-verified.',
                'messageKey' => 'jwksNotConfigured',
            ];
        }

        $violation = $this->urlValidator->validate($jwksEndpoint);

        if ($violation['blocked']) {
            return ['id' => 'jwks_reachable', 'status' => 'fail', 'detail' => implode(' ', $violation['warnings'])];
        }

        try {
            $document = $this->httpClient->getJson($jwksEndpoint, $timeout);
        } catch (OidcHttpException $exception) {
            return ['id' => 'jwks_reachable', 'status' => 'fail', 'detail' => $exception->getMessage()];
        }

        $keys = $document['keys'] ?? null;

        if (!\is_array($keys) || $keys === []) {
            return [
                'id' => 'jwks_reachable',
                'status' => 'fail',
                'detail' => 'JWKS endpoint responded but did not contain a non-empty "keys" array.',
                'messageKey' => 'jwksNoKeys',
            ];
        }

        if ($violation['warnings'] !== []) {
            return ['id' => 'jwks_reachable', 'status' => 'warning', 'detail' => implode(' ', $violation['warnings'])];
        }

        return [
            'id' => 'jwks_reachable',
            'status' => 'pass',
            'detail' => sprintf('JWKS endpoint returned %d key(s).', \count($keys)),
            'messageKey' => 'jwksPass',
            'messageParams' => ['count' => \count($keys)],
        ];
    }

    /**
     * @param array<int, array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}> $checks
     */
    private function overallStatus(array $checks): string
    {
        $statuses = array_column($checks, 'status');

        if (\in_array('fail', $statuses, true)) {
            return 'fail';
        }

        if (\in_array('warning', $statuses, true)) {
            return 'warning';
        }

        return 'pass';
    }

    private function nullIfEmpty(?string $value): ?string
    {
        return $value === null || $value === '' ? null : $value;
    }
}
