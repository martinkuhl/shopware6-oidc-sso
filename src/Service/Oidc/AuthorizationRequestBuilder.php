<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use Psr\Log\LoggerInterface;

/**
 * Builds the IdP authorize-endpoint redirect URL: starts a new
 * AuthorizationFlowContext (PKCE + nonce + state) and appends the standard
 * OIDC authorization-request query parameters. Shared by the Storefront and
 * Administration SP-initiated login controllers.
 */
class AuthorizationRequestBuilder
{
    public function __construct(
        private readonly OidcSecurityHelper $securityHelper,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param array<string, string> $extraParams additional authorize parameters (e.g. prompt=login for step-up)
     */
    public function build(
        Sw6OidcProviderEntity $provider,
        string $loginType,
        string $relayState,
        string $redirectUri,
        string $purpose = AuthorizationFlowContext::PURPOSE_LOGIN,
        ?string $expectedUserId = null,
        array $extraParams = [],
        ?string $locale = null,
    ): string {
        $flow = $this->securityHelper->beginAuthorizationRequest(
            $provider->getId(),
            $loginType,
            $relayState,
            $provider->getPkceFlow(),
            $purpose,
            $expectedUserId,
            $locale,
        );

        // The protocol parameters always win over extras.
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $provider->getClientId(),
            'redirect_uri' => $redirectUri,
            'scope' => $provider->getScope(),
            'state' => $flow['state'],
            'nonce' => $flow['nonce'],
            'code_challenge' => $flow['codeChallenge'],
            'code_challenge_method' => $provider->getPkceFlow(),
        ] + $extraParams);

        $separator = str_contains((string) $provider->getAuthorizeEndpoint(), '?') ? '&' : '?';

        $this->logger->debug('sw6oidc: redirecting to IdP authorize endpoint.', [
            'providerId' => $provider->getId(),
            'loginType' => $loginType,
            'purpose' => $purpose,
            'redirectUri' => $redirectUri,
        ]);

        return $provider->getAuthorizeEndpoint() . $separator . $query;
    }
}
