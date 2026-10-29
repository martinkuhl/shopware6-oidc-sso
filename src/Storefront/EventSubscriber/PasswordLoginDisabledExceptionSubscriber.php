<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Storefront\EventSubscriber;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use Shopware\Core\PlatformRequest;
use Shopware\Storefront\Framework\Routing\StorefrontRouteScope;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Storefront password login/registration while SSO-only mode is on: show the
 * explanation on the login page instead of an error page. Store API requests
 * keep the plain 403 JSON error.
 */
class PasswordLoginDisabledExceptionSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        // Before core's storefront error handling renders an error page.
        return [KernelEvents::EXCEPTION => ['onException', 10]];
    }

    public function onException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        if (!$exception instanceof PasswordLoginDisabledException) {
            return;
        }

        $request = $event->getRequest();
        $scopes = (array) $request->attributes->get(PlatformRequest::ATTRIBUTE_ROUTE_SCOPE, []);

        if (!\in_array(StorefrontRouteScope::ID, $scopes, true)) {
            return;
        }

        $session = $request->hasSession() ? $request->getSession() : null;

        if ($session instanceof FlashBagAwareSessionInterface) {
            $session->getFlashBag()->add('danger', $this->translator->trans($exception->getSnippetKey()));
        }

        $event->setResponse(new RedirectResponse($this->urlGenerator->generate('frontend.account.login.page')));
    }
}
