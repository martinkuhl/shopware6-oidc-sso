<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
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
 * OIDC Front-Channel Logout 1.0 receiver: the IdP's logout page embeds this
 * URL in a hidden iframe, with `iss` and `sid` query parameters
 * (`frontchannel_logout_session_required`). Every local session registered
 * for that IdP session is ended.
 *
 * Only `iss` + `sid` identify the session: the shop's own cookies are
 * SameSite and not sent in a cross-site iframe, so "log out whoever this
 * browser is" is not an option. Requests without both parameters do nothing.
 *
 * Always answers 200 with a 1×1 transparent GIF, whatever happened — the
 * IdP page must render the same either way, and nothing about the outcome
 * leaks to the embedding page. Only malformed requests count against
 * Sw6OidcRateLimiter (a blocked address still gets the GIF, but nothing is
 * processed); a sid that ends nothing is normal (RP logout or back-channel
 * logout got there first) and relies on sid entropy instead (N-M6).
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class FrontChannelLogoutController extends AbstractController
{
    /** 1×1 transparent GIF. */
    private const PIXEL = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

    public function __construct(
        private readonly ProviderResolver $providerResolver,
        private readonly Sw6OidcIdpLogoutHandler $logoutHandler,
        private readonly Sw6OidcRateLimiter $rateLimiter,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Route(
        path: '/sw6oidc/frontchannel-logout',
        name: 'frontend.sw6oidc.frontchannel-logout',
        defaults: ['_loginRequired' => false, '_httpCache' => false],
        methods: ['GET'],
    )]
    public function logout(Request $request): Response
    {
        $clientIp = $request->getClientIp();
        $issuer = $request->query->get('iss');
        $sid = $request->query->get('sid');

        // The budget only counts and blocks malformed requests: a NAT whose
        // clients sent junk must not lose its real logouts (R3-L9).
        if (!\is_string($issuer) || $issuer === '' || !\is_string($sid) || $sid === '') {
            if (!$this->rateLimiter->isBlocked(Sw6OidcRateLimiter::SCOPE_FRONTCHANNEL_LOGOUT, $clientIp)) {
                $this->rateLimiter->recordFailure(Sw6OidcRateLimiter::SCOPE_FRONTCHANNEL_LOGOUT, $clientIp);
                $this->logger->info('sw6oidc: front-channel logout without iss/sid, nothing to do.');
            }

            return $this->pixel();
        }

        $ended = 0;

        foreach ($this->providerResolver->findByIssuer($issuer, Context::createDefaultContext()) as $provider) {
            $ended += \count($this->logoutHandler->logout(
                $provider->getId(),
                null,
                $sid,
                Sw6OidcSessionActivityDefinition::LOGOUT_REASON_FRONTCHANNEL,
                $provider->isFrontchannelAdminLogout(),
            ));
        }

        // Ending nothing is the normal case (RP-initiated or back-channel
        // logout got there first, the session expired) and is not counted
        // as a failure — only malformed requests are (N-M6). A `sid` is a
        // high-entropy capability; guessing it is not practical.
        $this->logger->info('sw6oidc: front-channel logout processed.', ['sessionsEnded' => $ended]);

        return $this->pixel();
    }

    private function pixel(): Response
    {
        return new Response((string) base64_decode(self::PIXEL, true), Response::HTTP_OK, [
            'Content-Type' => 'image/gif',
            'Cache-Control' => 'no-cache, no-store',
            'Pragma' => 'no-cache',
            // The IdP embeds this in an iframe; core would add X-Frame-Options: deny,
            // which CSP frame-ancestors overrides. A 1x1 GIF has nothing to clickjack.
            'Content-Security-Policy' => 'frame-ancestors *',
        ]);
    }
}
