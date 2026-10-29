<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Oidc;

use MartinKuhl\Sw6Oidc\Service\Oidc\PostLogoutState;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Shared landing page after RP-Initiated Logout, for IdPs that accept only
 * one registered post-logout redirect URI: set a provider's "Post-logout
 * redirect URI" to `https://<shop>/sw6oidc/postlogout` and register just
 * that. The signed `state` (PostLogoutState) tells customer and admin logouts
 * apart; anything else lands on the Storefront login page.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class PostLogoutController extends AbstractController
{
    public function __construct(
        private readonly PostLogoutState $postLogoutState,
        private readonly string $administrationBaseUrl,
    ) {
    }

    #[Route(
        path: '/sw6oidc/postlogout',
        name: 'frontend.sw6oidc.postlogout',
        defaults: ['_loginRequired' => false, '_httpCache' => false],
        methods: ['GET'],
    )]
    public function landing(Request $request): RedirectResponse
    {
        $state = $request->query->get('state');

        if ($this->postLogoutState->parse(\is_string($state) ? $state : null) === PostLogoutState::TARGET_ADMIN) {
            return new RedirectResponse(rtrim($this->administrationBaseUrl, '/') . '/');
        }

        return new RedirectResponse($this->generateUrl('frontend.account.login.page'));
    }
}
