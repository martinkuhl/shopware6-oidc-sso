<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityCollection;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityEntity;
use MartinKuhl\Sw6Oidc\Service\Health\NodeHeartbeat;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\SystemSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\MultiFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Sorting\FieldSorting;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Writes the sw6oidc_session_activity log: one row per login, closed on
 * logout. Pure bookkeeping — every method swallows and logs its own errors,
 * so a failing audit write can never fail a login or logout.
 *
 * A logout is matched to its login row by the registry session id (OIDC
 * logins; the only thing Back-/Front-Channel Logout knows), else by the hash
 * of the local session key (context token / first access-token jti).
 */
class Sw6OidcSessionActivityRecorder
{
    private const CLOSE_BATCH_SIZE = 200;

    /**
     * @param EntityRepository<Sw6OidcSessionActivityCollection> $activityRepository
     */
    public function __construct(
        private readonly EntityRepository $activityRepository,
        private readonly LoggerInterface $logger,
        private readonly ?NodeHeartbeat $nodeHeartbeat = null,
        /** SW6OIDC_SESSION_ACTIVITY_TRUNCATE_IP: keep only IPv4 /24 and IPv6 /64 (N-L12) */
        private readonly bool $truncateIp = false,
    ) {
    }

    public function recordLogin(
        string $userType,
        string $userId,
        string $loginMethod,
        string $sessionKey,
        ?Request $request,
        ?string $providerId = null,
        ?Sw6OidcSession $registrySession = null,
        /** credential_id_hash of the passkey that logged in, so deleting it ends this session (R3-M6) */
        ?string $passkeyCredentialHash = null,
    ): void {
        try {
            $this->activityRepository->create([[
                'id' => Uuid::randomHex(),
                'providerId' => $providerId,
                'userType' => $userType,
                'userId' => $userId,
                'sub' => $registrySession?->sub,
                // A `sid` lets anyone end the IdP session: only its hash is kept (R3-L40).
                'sid' => $registrySession?->sid !== null ? self::hashSid($registrySession->sid) : null,
                'loginMethod' => $loginMethod,
                'sessionKeyHash' => $this->hash($sessionKey),
                'registrySessionId' => $registrySession?->id,
                'passkeyCredentialHash' => $passkeyCredentialHash,
                'ipAddress' => $this->ipAddress($request),
                'userAgent' => $this->userAgent($request),
                'loggedInAt' => new \DateTimeImmutable(),
            ]], $this->systemContext());
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: could not record session login.', ['exception' => $exception->getMessage()]);
        }

        // Every login path passes through here: a cheap way to learn which app servers serve SSO.
        $this->nodeHeartbeat?->record();
    }

    /**
     * Closes the open login row of exactly one session (by registry entry or
     * session key). Nothing matching means nothing is closed — guessing
     * "the newest row" would mark another device's session as logged out.
     */
    public function recordLogout(
        string $userType,
        string $userId,
        string $reason,
        ?string $sessionKey = null,
        ?string $registrySessionId = null,
    ): void {
        $identifiers = [];

        if ($registrySessionId !== null) {
            $identifiers[] = new EqualsFilter('registrySessionId', $registrySessionId);
        }

        if ($sessionKey !== null) {
            $identifiers[] = new EqualsFilter('sessionKeyHash', $this->hash($sessionKey));
        }

        if ($identifiers === []) {
            return;
        }

        try {
            // One indexed lookup instead of scanning the account's open rows (R3-L31).
            $this->close($this->openActivities($userType, $userId, new MultiFilter(MultiFilter::CONNECTION_OR, $identifiers), 1), $reason);
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: could not record session logout.', ['exception' => $exception->getMessage()]);
        }
    }

    /**
     * Closes every open login row of the account (all of an admin's sessions
     * end together, see Sw6OidcSessionDestructionService).
     */
    public function recordLogoutOfAllSessions(string $userType, string $userId, string $reason): void
    {
        try {
            // In batches, so an account with many open rows is closed completely (R3-L31).
            do {
                $batch = $this->openActivities($userType, $userId, null, self::CLOSE_BATCH_SIZE);
                $this->close($batch, $reason);
            } while (\count($batch) === self::CLOSE_BATCH_SIZE);
        } catch (\Throwable $exception) {
            $this->logger->warning('sw6oidc: could not record session logout.', ['exception' => $exception->getMessage()]);
        }
    }

    public function get(string $activityId): ?Sw6OidcSessionActivityEntity
    {
        $activity = $this->activityRepository->search(new Criteria([$activityId]), Context::createDefaultContext())->first();

        return $activity instanceof Sw6OidcSessionActivityEntity ? $activity : null;
    }

    /**
     * @return list<Sw6OidcSessionActivityEntity> newest first
     */
    private function openActivities(string $userType, string $userId, ?MultiFilter $identifiers, int $limit): array
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('userType', $userType))
            ->addFilter(new EqualsFilter('userId', $userId))
            ->addFilter(new EqualsFilter('loggedOutAt', null))
            ->addSorting(new FieldSorting('loggedInAt', FieldSorting::DESCENDING))
            ->setLimit($limit);

        if ($identifiers instanceof MultiFilter) {
            $criteria->addFilter($identifiers);
        }

        $activities = [];

        foreach ($this->activityRepository->search($criteria, Context::createDefaultContext())->getEntities() as $activity) {
            if ($activity instanceof Sw6OidcSessionActivityEntity) {
                $activities[] = $activity;
            }
        }

        return $activities;
    }

    /**
     * @param list<Sw6OidcSessionActivityEntity> $activities
     */
    private function close(array $activities, string $reason): void
    {
        if ($activities === []) {
            return;
        }

        $now = new \DateTimeImmutable();

        $this->activityRepository->update(array_map(
            static fn (Sw6OidcSessionActivityEntity $activity): array => ['id' => $activity->getId(), 'loggedOutAt' => $now, 'logoutReason' => $reason],
            $activities,
        ), $this->systemContext());
    }

    /**
     * The activity fields are WriteProtected(system) (N-M8).
     */
    private function systemContext(): Context
    {
        return new Context(new SystemSource());
    }

    private function userAgent(?Request $request): ?string
    {
        $userAgent = $request?->headers->get('User-Agent');

        return \is_string($userAgent) && $userAgent !== '' ? mb_substr($userAgent, 0, 512) : null;
    }

    /**
     * The stored form of an IdP session id: `sha256:<hex>`.
     */
    public static function hashSid(string $sid): string
    {
        return 'sha256:' . hash('sha256', $sid);
    }

    private function hash(string $sessionKey): string
    {
        return hash('sha256', $sessionKey);
    }

    private function ipAddress(?Request $request): ?string
    {
        $ip = $request?->getClientIp();

        return $ip !== null && $this->truncateIp ? IpUtils::anonymize($ip) : $ip;
    }
}
