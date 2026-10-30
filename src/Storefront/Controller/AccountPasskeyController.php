<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\Controller;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyCredentialRepository;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\PlatformRequest;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Self-service Passkey register/delete under My Account - lists and manages
 * only the currently logged-in customer's own credentials. Registration
 * itself is handled by the existing, unauthenticated-by-id
 * Storefront/Controller/PasskeyController::registrationOptions()/
 * registrationVerify() actions (already scoped to the logged-in customer via
 * its own injected CustomerEntity argument); this controller only adds the
 * page to list/delete them, mirroring the Administration "My passkeys"
 * profile tab's same ownership-checked delete pattern.
 */
#[Route(defaults: ['_routeScope' => ['storefront']])]
class AccountPasskeyController extends StorefrontController
{
    public function __construct(
        private readonly PasskeyCredentialRepository $passkeyCredentialRepository,
        private readonly PasskeyConfig $passkeyConfig,
        // The service id is core's LogoutRoute, but the plugin decorates it
        // (OidcLogoutRoute), so only the abstract type fits: the concrete
        // type hint made this controller fail to build (R7-H1).
        private readonly AbstractLogoutRoute $logoutRoute,
        private readonly SalesChannelContextPersister $contextPersister,
    ) {
    }

    #[Route(
        path: '/account/passkey',
        name: 'frontend.account.passkey.page',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true, 'XmlHttpRequest' => false],
        methods: ['GET'],
    )]
    public function index(SalesChannelContext $context, CustomerEntity $customer): Response
    {
        $credentials = $this->passkeyCredentialRepository->findAllForOwner(LoginType::Customer->value, $customer->getId(), $context->getContext());

        return $this->renderStorefront('@Sw6Oidc/storefront/page/account/passkey/index.html.twig', [
            'sw6oidcCredentials' => $credentials,
            'sw6oidcPasskeyEnabled' => $this->passkeyConfig->isEnabledForCustomer($context->getSalesChannelId()),
        ]);
    }

    #[Route(
        path: '/account/passkey/delete/{credentialId}',
        name: 'frontend.account.passkey.delete',
        defaults: [PlatformRequest::ATTRIBUTE_LOGIN_REQUIRED => true, 'XmlHttpRequest' => false],
        methods: ['POST'],
    )]
    public function delete(string $credentialId, Request $request, SalesChannelContext $context, CustomerEntity $customer): RedirectResponse
    {
        $deleted = $this->passkeyCredentialRepository->deleteOwnedByUser($credentialId, LoginType::Customer->value, $customer->getId(), $context->getContext());

        if (!$deleted) {
            $this->addFlash(self::DANGER, $this->trans('sw6oidc.passkey.deleteError'));

            return $this->redirectToRoute('frontend.account.passkey.page');
        }

        // Deleting a passkey ends the sessions it logged in
        // (PasskeyDeletionSubscriber, R3-M6). If that included this one, its
        // context token is gone: finish the logout here instead of leaving
        // the customer on an account page. Deleting another key, or one that
        // didn't log in this session, never triggers this (R8-L13).
        if ($this->contextPersister->load($context->getToken(), $context->getSalesChannelId(), $customer->getId()) === []) {
            $this->logoutRoute->logout($context, new RequestDataBag());
            $request->attributes->set(PlatformRequest::ATTRIBUTE_CLEAR_SITE_DATA, true);

            $this->addFlash(self::SUCCESS, $this->trans('sw6oidc.passkey.deleteSuccessLoggedOut'));

            return $this->redirectToRoute('frontend.account.login.page');
        }

        $this->addFlash(self::SUCCESS, $this->trans('sw6oidc.passkey.deleteSuccess'));

        return $this->redirectToRoute('frontend.account.passkey.page');
    }
}
