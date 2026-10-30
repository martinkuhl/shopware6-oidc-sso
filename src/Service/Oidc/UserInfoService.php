<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\OidcHttpClient;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;

/**
 * The userinfo claims, as JSON or — for a client registered for signed
 * userinfo — as a JWT verified against the provider's keys (OIDC Core
 * §5.3.2). Encrypted userinfo (JWE) isn't supported.
 */
class UserInfoService
{
    public function __construct(
        private readonly OidcHttpClient $httpClient,
        private readonly JwtVerifier $jwtVerifier,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function fetchClaims(Sw6OidcProviderEntity $provider, string $accessToken): array
    {
        if ($provider->getUserInfoEndpoint() === null) {
            return [];
        }

        $response = $this->httpClient->getUserInfo(
            $provider->getUserInfoEndpoint(),
            $accessToken,
            $provider->getHttpTimeout(),
        );

        return $response['claims'] ?? $this->jwtVerifier->verifyUserInfo(
            $response['jwt'],
            (string) $provider->getJwksEndpoint(),
            (string) $provider->getIssuer(),
            $provider->getClientId(),
            $provider->getJwksCacheTtl(),
            $provider->getHttpTimeout(),
        );
    }
}
