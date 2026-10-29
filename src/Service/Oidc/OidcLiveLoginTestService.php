<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcAccessControlEvaluator;
use Shopware\Core\Framework\Context;

/**
 * Runs the safe subset of OidcCallbackProcessor::process()'s pipeline for the
 * "Run live login test" admin feature: exchange the code for tokens, verify
 * the id_token (required with the openid scope), fetch userinfo, merge with
 * the same id_token-wins rules (ClaimsMerger), normalize groups and flatten
 * claims — the exact building blocks the real login callback uses, so the
 * test is a faithful end-to-end check of the provider configuration (L5).
 * The access-control rules are evaluated too, but only reported (status
 * "warning"): the tested account is not necessarily one that should pass.
 *
 * Deliberately stops *before* AttributeMapper::map() and never calls
 * AdminProvisioningService/CustomerProvisioningService, AdminLoginNonceService,
 * or the League AuthorizationServer — this is what keeps "a test never creates
 * a real account or mints a real token" a structural guarantee rather than a
 * conventionally-assumed one. Each stage is caught independently so a partial
 * failure (e.g. token exchange worked but JWT verification failed) is visible
 * in the report instead of surfacing as a single all-or-nothing exception.
 */
class OidcLiveLoginTestService
{
    public function __construct(
        private readonly TokenExchangeService $tokenExchangeService,
        private readonly UserInfoService $userInfoService,
        private readonly JwtVerifier $jwtVerifier,
        private readonly ClaimsNormalizer $claimsNormalizer,
        private readonly Sw6OidcAccessControlEvaluator $accessControlEvaluator,
    ) {
    }

    /**
     * @return array{
     *     status: string,
     *     steps: array<int, array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}>,
     *     claims: array<string, mixed>
     * }
     */
    public function run(
        Sw6OidcProviderEntity $provider,
        string $code,
        string $codeVerifier,
        string $redirectUri,
        string $expectedNonce,
    ): array {
        $steps = [];

        try {
            $tokens = $this->tokenExchangeService->exchangeCodeForTokens($provider, $code, $redirectUri, $codeVerifier);
        } catch (\Throwable $exception) {
            $steps[] = ['id' => 'token_exchange', 'status' => 'fail', 'detail' => $exception->getMessage()];

            return ['status' => 'fail', 'steps' => $steps, 'claims' => []];
        }

        if (!isset($tokens['access_token']) || !\is_string($tokens['access_token'])) {
            $steps[] = [
                'id' => 'token_exchange',
                'status' => 'fail',
                'detail' => 'Token endpoint response did not include an access_token.',
                'messageKey' => 'tokenExchangeNoAccessToken',
            ];

            return ['status' => 'fail', 'steps' => $steps, 'claims' => []];
        }

        $steps[] = [
            'id' => 'token_exchange',
            'status' => 'pass',
            'detail' => 'Authorization code exchanged for an access token successfully.',
            'messageKey' => 'tokenExchangePass',
        ];

        $idTokenClaims = [];

        if (isset($tokens['id_token']) && \is_string($tokens['id_token'])) {
            try {
                $idTokenClaims = $this->jwtVerifier->verify(
                    $tokens['id_token'],
                    (string) $provider->getJwksEndpoint(),
                    (string) $provider->getIssuer(),
                    $provider->getClientId(),
                    $expectedNonce,
                    $provider->getJwksCacheTtl(),
                    $provider->getHttpTimeout(),
                );
                $steps[] = [
                    'id' => 'id_token_verification',
                    'status' => 'pass',
                    'detail' => 'id_token signature and claims verified successfully.',
                    'messageKey' => 'idTokenVerificationPass',
                ];
            } catch (\Throwable $exception) {
                $steps[] = ['id' => 'id_token_verification', 'status' => 'fail', 'detail' => $exception->getMessage()];
            }
        } else {
            // A real login refuses this when openid is requested (M2).
            $required = ClaimsMerger::requestsOpenIdScope($provider->getScope());
            $steps[] = [
                'id' => 'id_token_verification',
                'status' => $required ? 'fail' : 'skipped',
                'detail' => 'Token response did not include an id_token.',
                'messageKey' => $required ? 'idTokenVerificationMissing' : 'idTokenVerificationSkipped',
            ];
        }

        $userInfoClaims = [];

        if ($provider->getUserInfoEndpoint() !== null) {
            try {
                $userInfoClaims = $this->userInfoService->fetchClaims($provider, $tokens['access_token']);
                $steps[] = ['id' => 'userinfo_fetch', 'status' => 'pass', 'detail' => 'Userinfo endpoint responded successfully.', 'messageKey' => 'userinfoFetchPass'];
            } catch (\Throwable $exception) {
                $steps[] = ['id' => 'userinfo_fetch', 'status' => 'fail', 'detail' => $exception->getMessage()];
            }
        } else {
            $steps[] = ['id' => 'userinfo_fetch', 'status' => 'skipped', 'detail' => 'No userinfo endpoint configured.', 'messageKey' => 'userinfoFetchSkipped'];
        }

        try {
            $merged = ClaimsMerger::merge($idTokenClaims, $userInfoClaims);
        } catch (\Throwable $exception) {
            $steps[] = ['id' => 'claims', 'status' => 'fail', 'detail' => $exception->getMessage(), 'messageKey' => 'claimsSubjectMismatch'];
            $merged = $idTokenClaims;
        }

        try {
            ClaimsMerger::requireSubject($merged);
        } catch (\Throwable $exception) {
            // Every real login with these claims fails (R3-L4).
            $steps[] = ['id' => 'subject', 'status' => 'fail', 'detail' => $exception->getMessage()];
        }

        try {
            $claims = $this->claimsNormalizer->flatten($merged, $provider->getBase64Claims());
        } catch (\Throwable $exception) {
            $steps[] = ['id' => 'claims', 'status' => 'fail', 'detail' => $exception->getMessage()];

            return ['status' => 'fail', 'steps' => $steps, 'claims' => []];
        }

        $groups = $this->claimsNormalizer->decodeGroups(
            $this->claimsNormalizer->normalizeGroups($merged[$provider->getGroupAttribute()] ?? null),
            $provider->getGroupAttribute(),
            $provider->getBase64Claims(),
        );
        $steps[] = $groups === []
            ? [
                'id' => 'groups',
                'status' => 'skipped',
                'detail' => 'No groups in the configured group claim.',
                'messageKey' => 'groupsNone',
                'messageParams' => ['claim' => $provider->getGroupAttribute()],
            ]
            : [
                'id' => 'groups',
                'status' => 'pass',
                'detail' => sprintf('%d group(s) found.', \count($groups)),
                'messageKey' => 'groupsFound',
                'messageParams' => ['count' => \count($groups)],
            ];

        try {
            $this->accessControlEvaluator->evaluate($provider->getId(), $claims, Context::createDefaultContext());
            $steps[] = ['id' => 'access_control', 'status' => 'pass', 'detail' => 'The access-control rules allow this account.', 'messageKey' => 'accessControlAllowed'];
        } catch (AccessControlDeniedException $exception) {
            $steps[] = [
                'id' => 'access_control',
                'status' => 'warning',
                'detail' => sprintf('This account would be denied by the rule on "%s".', $exception->claimKey),
                'messageKey' => 'accessControlDenied',
                'messageParams' => ['claim' => $exception->claimKey],
            ];
        }

        $statuses = array_column($steps, 'status');
        $status = \in_array('fail', $statuses, true) ? 'fail' : 'pass';

        return ['status' => $status, 'steps' => $steps, 'claims' => $claims];
    }
}
