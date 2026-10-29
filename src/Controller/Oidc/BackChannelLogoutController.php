<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Service\Cache\AtomicCacheInterface;
use MartinKuhl\Sw6Oidc\Service\Jwt\Exception\InvalidJwtException;
use MartinKuhl\Sw6Oidc\Service\Jwt\JwtVerifier;
use MartinKuhl\Sw6Oidc\Service\Provider\ProviderResolver;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcIdpLogoutHandler;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * OIDC Back-Channel Logout 1.0 receiver: the IdP POSTs a signed logout token
 * server-to-server; every local session registered for its `sid` (or `sub`)
 * is ended. Unauthenticated by design — the token signature is the only
 * trust anchor.
 *
 * Responses follow §2.8: 200 (with `Cache-Control: no-store`) on success,
 * including "nothing to log out"; 400 for any invalid request; 429 for invalid
 * tokens once an address has produced too many of them for that provider.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class BackChannelLogoutController extends AbstractController
{
    private const JTI_PREFIX = 'sw6oidc_bcl_jti_';
    /** Upper bound for remembering a jti. */
    private const MAX_JTI_TTL_SECONDS = 86400;

    public function __construct(
        private readonly JwtVerifier $jwtVerifier,
        private readonly ProviderResolver $providerResolver,
        private readonly Sw6OidcIdpLogoutHandler $logoutHandler,
        private readonly Sw6OidcRateLimiter $rateLimiter,
        private readonly AtomicCacheInterface $replayMarkers,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route(
        path: '/sw6oidc/backchannel-logout',
        name: 'frontend.sw6oidc.backchannel-logout',
        defaults: ['_loginRequired' => false, 'csrf_protected' => false, '_httpCache' => false],
        methods: ['POST'],
    )]
    public function logout(Request $request): Response
    {
        $clientIp = $request->getClientIp();

        try {
            $logoutToken = $this->logoutToken($request);
            $provider = $this->resolveProvider($logoutToken);
        } catch (InvalidJwtException $exception) {
            // Malformed or not addressed to any provider of this shop. Such a
            // token can never be valid here, so once the address's budget is
            // used up it is answered 429 without another log line (R3-L8).
            if ($this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_BACKCHANNEL_LOGOUT, $clientIp)) {
                return $this->respond(Response::HTTP_TOO_MANY_REQUESTS);
            }

            $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_BACKCHANNEL_LOGOUT, $clientIp);
            $this->logger->warning('sw6oidc: back-channel logout rejected.', ['reason' => $exception->getMessage()]);

            return $this->respond(Response::HTTP_BAD_REQUEST, true);
        }

        // Failures count per provider and address, and a correctly signed
        // token is never refused: SaaS IdPs share egress IPs across tenants,
        // so someone else's garbage must not block this IdP's real logout
        // tokens (N-M7).
        $failureScope = Sw6OidcRateLimiter::SCOPE_BACKCHANNEL_LOGOUT . ':' . $provider->getId();
        // Checked before verifying: a blocked caller is verified against the
        // cached keys only and can't force JWKS fetches (R3-M1); a correctly
        // signed token still passes.
        $blocked = $this->rateLimiter->isBlocked($failureScope, $clientIp);

        try {
            $claims = $this->jwtVerifier->verifyLogoutToken(
                $logoutToken,
                (string) $provider->getJwksEndpoint(),
                (string) $provider->getIssuer(),
                $provider->getClientId(),
                $provider->getJwksCacheTtl(),
                $provider->getHttpTimeout(),
                allowRefetch: !$blocked,
            );
        } catch (InvalidJwtException $exception) {
            $this->rateLimiter->recordFailure($failureScope, $clientIp);
            $this->logger->warning('sw6oidc: back-channel logout token rejected.', [
                'providerId' => $provider->getId(),
                'reason' => $exception->getMessage(),
            ]);

            return $this->respond($blocked ? Response::HTTP_TOO_MANY_REQUESTS : Response::HTTP_BAD_REQUEST, !$blocked);
        }

        $replayKey = $this->replayKey($claims);

        if (!$this->replayMarkers->addIfAbsent($replayKey, '1', $this->replayTtl($claims))) {
            $this->logger->info('sw6oidc: back-channel logout token replayed, ignoring.', ['providerId' => $provider->getId()]);

            return $this->respond(Response::HTTP_OK);
        }

        try {
            $this->logoutHandler->logout(
                $provider->getId(),
                \is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
                \is_string($claims['sid'] ?? null) ? $claims['sid'] : null,
                Sw6OidcSessionActivityDefinition::LOGOUT_REASON_BACKCHANNEL,
            );
        } catch (\Throwable $exception) {
            // Not done: forget the token, so the IdP's retry is processed
            // instead of being taken for a replay (R3-M19).
            $this->replayMarkers->delete($replayKey);
            $this->logger->error('sw6oidc: back-channel logout failed; the IdP may retry.', [
                'providerId' => $provider->getId(),
                'exceptionClass' => $exception::class,
                'exception' => $exception->getMessage(),
            ]);

            return $this->respond(Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->respond(Response::HTTP_OK);
    }

    /**
     * @throws InvalidJwtException
     */
    private function logoutToken(Request $request): string
    {
        $logoutToken = $request->request->get('logout_token');

        if (!\is_string($logoutToken) || $logoutToken === '') {
            throw new InvalidJwtException('Missing "logout_token".');
        }

        return $logoutToken;
    }

    /**
     * The unverified `iss`/`aud` only pick which provider's keys verify the
     * token; several providers may share an issuer, so the audience decides.
     *
     * @throws InvalidJwtException
     */
    private function resolveProvider(string $logoutToken): Sw6OidcProviderEntity
    {
        $unverified = $this->jwtVerifier->decodeUnverified($logoutToken) ?? [];
        $issuer = \is_string($unverified['iss'] ?? null) ? $unverified['iss'] : '';
        $audiences = (array) ($unverified['aud'] ?? []);

        foreach ($this->providerResolver->findByIssuer($issuer, Context::createDefaultContext()) as $candidate) {
            if (\in_array($candidate->getClientId(), $audiences, true)) {
                return $candidate;
            }
        }

        throw new InvalidJwtException('No active provider matches the logout token issuer/audience.');
    }

    /**
     * OIDC Back-Channel Logout §2.6 step 7: a jti seen before is a replay.
     * An atomic set-if-absent in the shared one-time-token store (keyed by
     * issuer and jti), remembered until the token's own `exp` plus clock
     * leeway (replayTtl()).
     *
     * @param array<string, mixed> $claims verified; `jti` is guaranteed by the verifier
     */
    private function replayKey(array $claims): string
    {
        return self::JTI_PREFIX . hash('sha256', ($claims['iss'] ?? '') . "\0" . $claims['jti']);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function replayTtl(array $claims): int
    {
        return max(60, min(self::MAX_JTI_TTL_SECONDS, (int) ($claims['exp'] ?? 0) - time() + JwtVerifier::LEEWAY_SECONDS));
    }

    /**
     * Invalid requests get a fixed `invalid_request` error: which check
     * failed (unknown issuer, bad signature, JWKS trouble) is logged, never
     * told to an anonymous caller (N-L1).
     */
    private function respond(int $status, bool $invalidRequest = false): Response
    {
        $response = $invalidRequest
            ? new Response((string) json_encode(['error' => 'invalid_request']), $status, ['Content-Type' => 'application/json'])
            : new Response('', $status);

        $response->headers->set('Cache-Control', 'no-cache, no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
