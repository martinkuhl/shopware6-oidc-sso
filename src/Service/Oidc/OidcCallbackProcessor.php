<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\AttributeMapper;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcAccessControlEvaluator;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * The shared post-redirect half of the OIDC flow: redeem state, exchange the
 * code for tokens, verify the id_token, fetch userinfo, normalize claims, and
 * map attributes. Used by both the Storefront and Administration callback
 * controllers so the two flows can never drift apart on JWT/claims handling.
 */
class OidcCallbackProcessor
{
    private const MAX_IDP_ERROR_LENGTH = 64;
    private const MAX_IDP_ERROR_DESCRIPTION_LENGTH = 200;

    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly OidcSecurityHelper $securityHelper,
        private readonly TokenExchangeService $tokenExchangeService,
        private readonly UserInfoService $userInfoService,
        private readonly JwtVerifier $jwtVerifier,
        private readonly ClaimsNormalizer $claimsNormalizer,
        private readonly AttributeMapper $attributeMapper,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcAccessControlEvaluator $accessControlEvaluator,
    ) {
    }

    /**
     * An OAuth error response from the IdP (`?error=…`): ends the flow it
     * belongs to and returns it, or null when the `state` names no flow of
     * this login type started in this browser — then the request may be
     * forged and the caller counts it as a failure (R4-L4).
     */
    public function abortFlowWithIdpError(?string $state, string $expectedLoginType): ?AuthorizationFlowContext
    {
        try {
            return $this->consumeFlow($state, $expectedLoginType);
        } catch (InvalidStateException) {
            return null;
        }
    }

    /**
     * Log context for an IdP error response: both values come straight from
     * the query string, so they are cut short (R4-L4).
     *
     * @return array{error: string, error_description: string}
     */
    public static function idpErrorLogContext(mixed $error, mixed $description): array
    {
        return [
            'error' => mb_substr(\is_string($error) ? $error : '', 0, self::MAX_IDP_ERROR_LENGTH),
            'error_description' => mb_substr(\is_string($description) ? $description : '', 0, self::MAX_IDP_ERROR_DESCRIPTION_LENGTH),
        ];
    }

    /**
     * @param string $expectedLoginType the login type of the callback endpoint ('customer' or 'admin');
     *                                  a flow started for the other one is rejected
     *
     * @throws InvalidStateException
     * @throws \MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\MissingEmailClaimException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException
     * @throws \MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException
     */
    public function process(?string $code, ?string $state, string $redirectUri, string $expectedLoginType, Context $context): OidcCallbackResult
    {
        return $this->processFlow($this->consumeFlow($state, $expectedLoginType), $code, $redirectUri, $context);
    }

    /**
     * The first half of process(): redeems the state. Callers that must know
     * the flow's purpose even when the rest of the pipeline fails (the
     * Administration's step-up popup) call this and processFlow() separately.
     *
     * @throws InvalidStateException
     */
    public function consumeFlow(?string $state, string $expectedLoginType): AuthorizationFlowContext
    {
        $flow = $this->securityHelper->consumeAuthorizationFlow($state);

        if ($flow->loginType !== $expectedLoginType) {
            throw new InvalidStateException(sprintf(
                'OAuth state was issued for a "%s" login, not "%s".',
                $flow->loginType,
                $expectedLoginType,
            ));
        }

        return $flow;
    }

    /**
     * The second half of process(), for a flow from consumeFlow().
     *
     * @throws InvalidStateException
     * @throws \MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\MissingEmailClaimException
     * @throws \MartinKuhl\Sw6Oidc\Service\Provider\Exception\ProviderNotFoundException
     * @throws \MartinKuhl\Sw6Oidc\Service\Security\Exception\AccessControlDeniedException
     */
    public function processFlow(AuthorizationFlowContext $flow, ?string $code, string $redirectUri, Context $context): OidcCallbackResult
    {
        if ($code === null || $code === '') {
            throw new InvalidStateException('Callback is missing the "code" parameter.');
        }

        // Re-checked here, not only at flow start: the provider may have been
        // deactivated or re-scoped while the user was at the IdP.
        $provider = $this->providerResolver->getActiveById($flow->providerId, $flow->loginType, $context);

        $tokens = $this->tokenExchangeService->exchangeCodeForTokens($provider, $code, $redirectUri, $flow->codeVerifier);

        $this->logger->debug('sw6oidc: token exchange completed.', [
            'providerId' => $provider->getId(),
            'tokenKeys' => array_keys($tokens),
        ]);

        if (!isset($tokens['access_token']) || !\is_string($tokens['access_token'])) {
            throw new InvalidStateException('Token endpoint response did not include an access_token.');
        }

        $idTokenClaims = [];

        if (isset($tokens['id_token']) && \is_string($tokens['id_token'])) {
            $idTokenClaims = $this->jwtVerifier->verify(
                $tokens['id_token'],
                (string) $provider->getJwksEndpoint(),
                (string) $provider->getIssuer(),
                $provider->getClientId(),
                $flow->nonce,
                $provider->getJwksCacheTtl(),
                $provider->getHttpTimeout(),
            );
        } elseif (ClaimsMerger::requestsOpenIdScope($provider->getScope())) {
            // OIDC Core §3.1.3.3: an openid request always yields an id_token.
            // Its absence means the only signed statement about the user is
            // missing, so userinfo alone is not trusted.
            throw new InvalidStateException('Token response did not include the id_token required for the "openid" scope.');
        } else {
            $this->logger->warning('sw6oidc: provider does not request the "openid" scope; relying on userinfo alone.', [
                'providerId' => $provider->getId(),
            ]);
        }

        $userInfoClaims = $this->userInfoService->fetchClaims($provider, $tokens['access_token']);
        $mergedClaims = ClaimsMerger::merge($idTokenClaims, $userInfoClaims);
        ClaimsMerger::requireSubject($mergedClaims);

        $this->logger->debug('sw6oidc: userinfo fetched and merged with id_token claims.', [
            'providerId' => $provider->getId(),
            'userInfoClaimKeys' => array_keys($userInfoClaims),
            'mergedClaimKeys' => array_keys($mergedClaims),
        ]);

        // Extracted from the *unflattened* claims: flattening a Zitadel-style
        // nested role object would turn its group-name keys into dotted leaf
        // paths and lose them (see ClaimsNormalizer::normalizeGroups()).
        $rawGroupsClaim = $mergedClaims[$provider->getGroupAttribute()] ?? null;
        $groups = $this->claimsNormalizer->decodeGroups(
            $this->claimsNormalizer->normalizeGroups($rawGroupsClaim),
            $provider->getGroupAttribute(),
            $provider->getBase64Claims(),
        );

        $flattenedClaims = $this->claimsNormalizer->flatten($mergedClaims, $provider->getBase64Claims());

        // Before mapping, so a denied login never reaches lookup/JIT-create/sync.
        $this->accessControlEvaluator->evaluate($provider->getId(), $flattenedClaims, $context);

        $profile = $this->attributeMapper->map($provider, $flattenedClaims, $groups, $context);

        $this->logger->debug('sw6oidc: claims mapped to profile.', [
            'providerId' => $provider->getId(),
            'groupCount' => \count($groups),
        ]);

        return new OidcCallbackResult($provider, $flow, $profile, $tokens, $idTokenClaims, $mergedClaims);
    }
}
