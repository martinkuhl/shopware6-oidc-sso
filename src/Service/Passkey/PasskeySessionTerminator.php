<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionActivityRecorder;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Deleting a passkey ends the sessions it logged in (R3-M6): a user who
 * removes a lost or stolen key must not leave the attacker's sessions
 * running. The session activity log knows which open sessions a key started.
 *
 * - Customers: exactly those Store API contexts end (matched by the hash of
 *   their context token).
 * - Admins: access tokens are stateless and refresh tokens can't be mapped
 *   to a login, so *all* of the admin's sessions end, the current one
 *   included (as for forced logouts).
 */
class PasskeySessionTerminator
{
    public function __construct(
        private readonly Connection $connection,
        private readonly Sw6OidcSessionDestructionService $destructionService,
        private readonly Sw6OidcSessionActivityRecorder $activityRecorder,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @return bool whether any session was ended
     */
    public function endSessionsOf(string $userType, string $userId, string $credentialIdHash): bool
    {
        /** @var list<array{id: string, session_key_hash: string|null}> $rows */
        $rows = $this->connection->fetchAllAssociative(
            'SELECT `id`, `session_key_hash` FROM `sw6oidc_session_activity`
             WHERE `passkey_credential_hash` = :hash AND `user_type` = :userType AND `user_id` = :userId AND `logged_out_at` IS NULL',
            ['hash' => $credentialIdHash, 'userType' => $userType, 'userId' => Uuid::fromHexToBytes($userId)],
        );

        if ($rows === []) {
            return false;
        }

        if ($userType === LoginType::Admin->value) {
            $this->destructionService->destroyAdminSessions($userId);
            $this->activityRecorder->recordLogoutOfAllSessions($userType, $userId, Sw6OidcSessionActivityDefinition::LOGOUT_REASON_FORCED);
        } else {
            $this->endCustomerContexts($userId, array_values(array_filter(array_column($rows, 'session_key_hash'), static fn (?string $hash): bool => $hash !== null)));
            $this->closeRows(array_column($rows, 'id'));
        }

        $this->logger->warning('sw6oidc: passkey deleted; ended the sessions it logged in.', [
            'userType' => $userType,
            'userId' => $userId,
            'sessions' => \count($rows),
        ]);

        return true;
    }

    /**
     * @param list<string> $tokenHashes sha256 of the context tokens
     */
    private function endCustomerContexts(string $customerId, array $tokenHashes): void
    {
        if ($tokenHashes === []) {
            return;
        }

        $this->connection->executeStatement(
            'DELETE FROM `sales_channel_api_context` WHERE `customer_id` = :customerId AND SHA2(`token`, 256) IN (:hashes)',
            ['customerId' => Uuid::fromHexToBytes($customerId), 'hashes' => $tokenHashes],
            ['hashes' => ArrayParameterType::STRING],
        );
    }

    /**
     * @param list<string> $ids binary activity ids
     */
    private function closeRows(array $ids): void
    {
        $this->connection->executeStatement(
            'UPDATE `sw6oidc_session_activity` SET `logged_out_at` = :now, `logout_reason` = :reason WHERE `id` IN (:ids)',
            [
                'now' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                'reason' => Sw6OidcSessionActivityDefinition::LOGOUT_REASON_FORCED,
                'ids' => $ids,
            ],
            ['ids' => ArrayParameterType::BINARY],
        );
    }
}
