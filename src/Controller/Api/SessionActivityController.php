<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityEntity;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSession;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

/**
 * "Force logout" for the session activity module (sw6oidc-sessions).
 *
 * A customer OIDC session still in the registry is ended exactly; everything
 * else — Passkey logins (not in the registry), and admins (whose sessions can
 * only be ended together) — ends **all** sessions of that account, and every
 * open activity row of the account is closed as `forced`.
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class SessionActivityController extends AbstractController
{
    public function __construct(
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcSessionDestructionService $destructionService,
        private readonly LoggerInterface $logger,
        private readonly string $adminSessionLifetime,
        private readonly string $customerSessionLifetime,
    ) {
    }

    /**
     * How long a session can live without a recorded logout, per account
     * type: the list labels older open rows as expired instead of active
     * (F-N3). Admin: refresh-token TTL; customer: Store API context lifetime.
     */
    #[Route(
        path: '/api/_action/sw6oidc/session-activity/settings',
        name: 'api.action.sw6oidc.session-activity.settings',
        defaults: ['_acl' => ['sw6oidc_session_activity:read']],
        methods: ['GET'],
    )]
    public function settings(): JsonResponse
    {
        return new JsonResponse([
            'sessionLifetimeSeconds' => [
                Sw6OidcSession::USER_TYPE_ADMIN => $this->seconds($this->adminSessionLifetime, 604800),
                Sw6OidcSession::USER_TYPE_CUSTOMER => $this->seconds($this->customerSessionLifetime, 86400),
            ],
        ]);
    }

    private function seconds(string $interval, int $fallback): int
    {
        try {
            $now = new \DateTimeImmutable('@0');

            return $now->add(new \DateInterval($interval))->getTimestamp();
        } catch (\Throwable) {
            return $fallback;
        }
    }

    #[Route(
        path: '/api/_action/sw6oidc/session-activity/{activityId}/force-logout',
        name: 'api.action.sw6oidc.session-activity.force-logout',
        defaults: ['_acl' => ['sw6oidc_session_activity:force_logout']],
        methods: ['POST'],
    )]
    public function forceLogout(string $activityId, Context $context): JsonResponse
    {
        $activity = Uuid::isValid($activityId) ? $this->activityRecorder->get($activityId) : null;

        if (!$activity instanceof Sw6OidcSessionActivityEntity) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        // Ending an Administration user's sessions (all of them: admin tokens
        // can't be targeted) is a superadmin's call, not every role holding
        // force_logout (R3-L37).
        $source = $context->getSource();

        if ($activity->getUserType() === Sw6OidcSession::USER_TYPE_ADMIN && $source instanceof AdminApiSource && !$source->isAdmin()) {
            return new JsonResponse(['error' => 'superadmin_required'], 403);
        }

        if ($activity->getLoggedOutAt() instanceof \DateTimeInterface) {
            return new JsonResponse(['alreadyLoggedOut' => true, 'endedAllSessions' => false]);
        }

        $userType = $activity->getUserType();
        $userId = $activity->getUserId();
        $registrySession = $activity->getRegistrySessionId() !== null ? $this->sessionRegistry->get($activity->getRegistrySessionId()) : null;

        if ($registrySession instanceof Sw6OidcSession && $userType === Sw6OidcSession::USER_TYPE_CUSTOMER) {
            $this->sessionRegistry->remove($registrySession);
            $this->destructionService->destroy($registrySession);
            $this->activityRecorder->recordLogout($userType, $userId, Sw6OidcSessionActivityDefinition::LOGOUT_REASON_FORCED, null, $registrySession->id);
            $endedAll = false;
        } else {
            $this->destructionService->destroyAllForUser($userType, $userId);

            $this->sessionRegistry->removeAllForUser($userType, $userId);

            $this->activityRecorder->recordLogoutOfAllSessions($userType, $userId, Sw6OidcSessionActivityDefinition::LOGOUT_REASON_FORCED);
            $endedAll = true;
        }

        $this->logger->info('sw6oidc: session force-logged-out by an administrator.', [
            'activityId' => $activityId,
            'userType' => $userType,
            'userId' => $userId,
            'endedAllSessions' => $endedAll,
        ]);

        return new JsonResponse(['alreadyLoggedOut' => false, 'endedAllSessions' => $endedAll]);
    }
}
