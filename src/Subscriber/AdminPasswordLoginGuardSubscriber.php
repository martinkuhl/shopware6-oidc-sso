<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\PasswordLoginDisabledException;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\PasswordLoginGuardClientRepository;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use Shopware\Core\Framework\Context;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * While disable_non_oidc_admin_login is on, answers non-SSO logins at
 * /api/oauth/token with a descriptive 403 instead of a bare invalid_grant:
 *
 *  - `password` grants (also refused by PasswordLoginGuardUserRepository,
 *    which is the actual enforcement);
 *  - `client_credentials` with a *user* access key (SWUA…): those log in as
 *    the key's admin without SSO. Integration keys (SWIA…) are unaffected.
 *    Opt out with SW6OIDC_ALLOW_USER_ACCESS_KEYS=1.
 *
 * The body is read the way the token endpoint itself reads it (Symfony's
 * PsrHttpFactory JSON-decodes every `json`-format content type, including
 * application/x-json and application/*+json), and a request whose grant type
 * can't be determined is refused rather than waved through.
 */
class AdminPasswordLoginGuardSubscriber implements EventSubscriberInterface
{
    public const ERROR_CODE = PasswordLoginDisabledException::ERROR_CODE;

    public function __construct(
        private readonly PasswordLoginPolicy $passwordLoginPolicy,
        private readonly bool $allowUserAccessKeys = false,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        // After the router (32) so _route is set, before the controller.
        return [KernelEvents::REQUEST => ['onRequest', 8]];
    }

    public function onRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();

        if (!$event->isMainRequest() || $request->attributes->get('_route') !== 'api.oauth.token') {
            return;
        }

        $body = $this->parseBody($request);
        $grantType = $body['grant_type'] ?? null;

        if (\is_string($grantType) && !$this->isNonSsoLogin($grantType, $body, $request)) {
            return;
        }

        if (!$this->passwordLoginPolicy->isPasswordLoginDisabled(LoginType::Admin->value, Context::createDefaultContext())) {
            return;
        }

        $message = 'Password login is disabled for the Administration. Please sign in with single sign-on or a passkey.';

        $event->setResponse(new JsonResponse([
            // RFC 6749 §5.2 shape for OAuth clients, plus Shopware's errors[] for the Admin UI.
            'error' => 'access_denied',
            'error_description' => $message,
            'errors' => [[
                'status' => (string) Response::HTTP_FORBIDDEN,
                'code' => self::ERROR_CODE,
                'title' => 'Forbidden',
                'detail' => $message,
            ]],
        ], Response::HTTP_FORBIDDEN));
    }

    /**
     * @param array<mixed> $body
     */
    private function isNonSsoLogin(string $grantType, array $body, Request $request): bool
    {
        if ($grantType === 'password') {
            return true;
        }

        if ($grantType !== 'client_credentials' || $this->allowUserAccessKeys) {
            return false;
        }

        // Like League: trimmed, and an empty client_id falls back to Basic auth (R3-M20).
        $clientId = \is_string($body['client_id'] ?? null) ? trim($body['client_id']) : '';

        if ($clientId === '') {
            $clientId = (string) $request->getUser();
        }

        return PasswordLoginGuardClientRepository::isUserAccessKey($clientId);
    }

    /**
     * @return array<mixed>
     */
    private function parseBody(Request $request): array
    {
        if ($request->getContentTypeFormat() === 'json') {
            try {
                $decoded = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return [];
            }

            return \is_array($decoded) ? $decoded : [];
        }

        return $request->request->all();
    }
}
