<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use Psr\Log\LoggerInterface;

/**
 * The shared "the IdP says this session is over" step behind Back- and
 * Front-Channel Logout: look the sessions up in the registry, remove them,
 * destroy the local sessions. Protocol validation (token signature, iss/sid
 * query parameters) stays in the controllers.
 */
class Sw6OidcIdpLogoutHandler
{
    public function __construct(
        private readonly Sw6OidcSessionRegistry $registry,
        private readonly Sw6OidcSessionDestructionService $destructionService,
        private readonly LoggerInterface $logger,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
    ) {
    }

    /**
     * Ends the IdP session `sid` (when given), else every session of `sub`.
     * Idempotent: nothing registered (already logged out, unknown) is not an
     * error.
     *
     * @param string $reason        Sw6OidcSessionActivityDefinition::LOGOUT_REASON_* for the activity log
     * @param bool   $includeAdmins whether Administration sessions may be ended (they can only be
     *                              ended all at once; front-channel requests only do it on opt-in)
     *
     * @return list<Sw6OidcSession> the sessions that were ended
     */
    public function logout(string $providerId, ?string $sub, ?string $sid, string $reason, bool $includeAdmins = true): array
    {
        if ($sid !== null && $sid !== '') {
            $sessions = $this->registry->resolveBySid($providerId, $sid);

            // When both are present they must agree (OIDC Back-Channel Logout §2.4).
            if ($sub !== null && $sub !== '') {
                $sessions = array_values(array_filter($sessions, static fn (Sw6OidcSession $session): bool => $session->sub === $sub));
            }
        } elseif ($sub !== null && $sub !== '') {
            $sessions = $this->registry->resolve($providerId, $sub);
        } else {
            return [];
        }

        if (!$includeAdmins) {
            $skipped = \count($sessions);
            $sessions = array_values(array_filter($sessions, static fn (Sw6OidcSession $session): bool => $session->userType !== Sw6OidcSession::USER_TYPE_ADMIN));

            if ($skipped !== \count($sessions)) {
                $this->logger->info('sw6oidc: front-channel logout left Administration sessions alone (frontchannel_admin_logout is off).', [
                    'providerId' => $providerId,
                ]);
            }
        }

        $destroyedAdmins = [];

        // Destroy first, then forget: if destroying fails, the entry stays
        // and the IdP's retry can still find the session (R3-M19).
        foreach ($sessions as $session) {
            if ($session->userType === Sw6OidcSession::USER_TYPE_ADMIN) {
                // Admin destruction is per user anyway; once is enough.
                if (isset($destroyedAdmins[$session->userId])) {
                    continue;
                }

                $this->destructionService->destroy($session);
                $destroyedAdmins[$session->userId] = true;
                $this->activityRecorder->recordLogoutOfAllSessions($session->userType, $session->userId, $reason);

                // Every session of this admin is dead now, not only the
                // sid-matched ones: drop all their registry entries so later
                // logouts don't act on stale ones (N-L3).
                $this->registry->removeAllForUser($session->userType, $session->userId);

                continue;
            }

            $this->destructionService->destroy($session);
            $this->activityRecorder->recordLogout($session->userType, $session->userId, $reason, $session->sessionKey, $session->id);
            $this->registry->remove($session);
        }

        $this->logger->info('sw6oidc: IdP-initiated logout processed.', [
            'providerId' => $providerId,
            'bySid' => $sid !== null && $sid !== '',
            'sessionsEnded' => \count($sessions),
        ]);

        return $sessions;
    }
}
