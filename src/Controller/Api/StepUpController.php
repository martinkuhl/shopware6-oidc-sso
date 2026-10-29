<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use MartinKuhl\Sw6Oidc\Service\AdminAuth\AdminTokenIssuer;
use MartinKuhl\Sw6Oidc\Service\AdminAuth\StepUpService;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Service\Security\PublicError;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcRateLimiter;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Fresh re-authentication for the logged-in admin (see StepUpService),
 * offered by the `sw-verify-user-modal` override next to the password field
 * so SSO and passkey admins can confirm sensitive changes too. Every action
 * requires an authenticated Administration session and only ever acts on
 * that session's own user.
 */
#[Route(defaults: ['_routeScope' => ['api'], 'auth_required' => true])]
class StepUpController extends AbstractController
{
    public function __construct(
        private readonly StepUpService $stepUpService,
        private readonly AdminTokenIssuer $tokenIssuer,
        private readonly PasskeyConfig $passkeyConfig,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcRateLimiter $rateLimiter,
    ) {
    }

    /**
     * Which re-authentication methods the current admin can use.
     */
    #[Route(path: '/api/sw6oidc/admin/step-up/methods', name: 'api.action.sw6oidc.admin.step-up.methods', methods: ['GET'])]
    public function methods(Context $context): JsonResponse
    {
        $userId = $this->currentUserId($context);

        return new JsonResponse([
            'oidc' => $userId !== null && $this->stepUpService->hasOidc($userId, $context),
            'passkey' => $userId !== null && $this->passkeyConfig->isEnabledForAdmin() && $this->stepUpService->hasPasskey($userId),
        ]);
    }

    #[Route(path: '/api/sw6oidc/admin/step-up/oidc/start', name: 'api.action.sw6oidc.admin.step-up.oidc-start', methods: ['POST'])]
    public function startOidc(Request $request, Context $context): JsonResponse
    {
        $userId = $this->currentUserId($context);

        if ($userId !== null && !$this->flowStartAllowed($userId, $request)) {
            return new JsonResponse(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }
        $authorizeUrl = $userId !== null ? $this->stepUpService->oidcAuthorizeUrl($userId, $this->callbackUrl(), $context) : null;

        if ($authorizeUrl === null) {
            return new JsonResponse(['error' => 'step_up_unavailable'], Response::HTTP_NOT_FOUND);
        }

        return new JsonResponse(['authorizeUrl' => $authorizeUrl]);
    }

    /**
     * Redeems the nonce the OIDC step-up popup handed back to the
     * Administration window.
     */
    #[Route(path: '/api/sw6oidc/admin/step-up/token', name: 'api.action.sw6oidc.admin.step-up.token', methods: ['POST'])]
    public function token(Request $request, Context $context): Response
    {
        $userId = $this->currentUserId($context);

        if ($userId !== null && $this->rateLimiter->isBlocked($this->failureScope($userId), $request->getClientIp())) {
            return new JsonResponse(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }

        if ($userId === null || !$this->stepUpService->redeemNonce((string) $request->request->get('nonce'), $userId)) {
            if ($userId !== null) {
                $this->rateLimiter->recordFailure($this->failureScope($userId), $request->getClientIp());
            }

            return new JsonResponse(['error' => 'invalid_grant'], Response::HTTP_BAD_REQUEST);
        }

        return $this->issue($userId);
    }

    #[Route(path: '/api/sw6oidc/admin/step-up/passkey/options', name: 'api.action.sw6oidc.admin.step-up.passkey-options', methods: ['POST'])]
    public function passkeyOptions(Request $request, Context $context): JsonResponse
    {
        $userId = $this->currentUserId($context);

        if ($userId !== null && !$this->flowStartAllowed($userId, $request)) {
            return new JsonResponse(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }
        $options = $userId !== null && $this->passkeyConfig->isEnabledForAdmin() ? $this->stepUpService->passkeyOptions($userId) : null;

        if ($options === null) {
            return new JsonResponse(['error' => 'step_up_unavailable'], Response::HTTP_NOT_FOUND);
        }

        return new JsonResponse(['sessionId' => $options['nonce'], 'options' => json_decode($options['optionsJson'], true)]);
    }

    #[Route(path: '/api/sw6oidc/admin/step-up/passkey/verify', name: 'api.action.sw6oidc.admin.step-up.passkey-verify', methods: ['POST'])]
    public function passkeyVerify(Request $request, Context $context): Response
    {
        $userId = $this->currentUserId($context);

        if ($userId === null || !$this->passkeyConfig->isEnabledForAdmin()) {
            return new JsonResponse(['error' => 'step_up_unavailable'], Response::HTTP_NOT_FOUND);
        }

        if ($this->rateLimiter->isBlocked($this->failureScope($userId), $request->getClientIp())) {
            return new JsonResponse(['error' => 'too_many_requests'], Response::HTTP_TOO_MANY_REQUESTS);
        }

        try {
            $this->stepUpService->verifyPasskey(
                (string) $request->request->get('sessionId'),
                (string) $request->request->get('credential'),
                $request->getHost(),
                $userId,
            );
        } catch (\Throwable $exception) {
            $this->rateLimiter->recordFailure($this->failureScope($userId), $request->getClientIp());

            return PublicError::response($this->logger, 'sw6oidc: passkey step-up failed.', $exception, 'step_up_failed', Response::HTTP_FORBIDDEN, ['userId' => $userId]);
        }

        return $this->issue($userId);
    }

    /**
     * Per admin and address: a failing step-up must not lock out other admins.
     */
    private function failureScope(string $userId): string
    {
        return Sw6OidcRateLimiter::SCOPE_REDEEM . ':step_up:' . $userId;
    }

    private function issue(string $userId): Response
    {
        try {
            $response = $this->tokenIssuer->issue($userId, true);
        } catch (\Throwable $exception) {
            return PublicError::response(
                $this->logger,
                'sw6oidc: step-up token could not be issued.',
                $exception,
                'invalid_grant',
                Response::HTTP_BAD_REQUEST,
                ['userId' => $userId],
            );
        }

        $this->logger->info('sw6oidc: admin completed a step-up re-authentication.', ['userId' => $userId]);

        return $response;
    }

    private function currentUserId(Context $context): ?string
    {
        $source = $context->getSource();

        return $source instanceof AdminApiSource ? $source->getUserId() : null;
    }

    private function callbackUrl(): string
    {
        return $this->generateUrl('api.action.sw6oidc.admin.callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
    }

    /**
     * Every start stores a flow or ceremony: a consuming budget per admin and
     * address, like the anonymous flow starts (R3-L41).
     */
    private function flowStartAllowed(string $userId, Request $request): bool
    {
        return $this->rateLimiter->consume(Sw6OidcRateLimiter::SCOPE_FLOW_START . ':' . $userId, $request->getClientIp());
    }
}
