<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Session;

use Doctrine\DBAL\Connection;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Api\OAuth\RefreshTokenRepository;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextPersister;

/**
 * Ends the local session behind a registry entry. The two sides differ:
 *
 * - **Customer**: exactly that session. Deleting the sales-channel context
 *   row makes the next request with that `sw-context-token` load an empty
 *   (anonymous) context — the customer has to log in again.
 * - **Admin**: every session of that admin user. Shopware admin access
 *   tokens are stateless JWTs (`AccessTokenRepository::revokeAccessToken()`
 *   is a no-op) and refresh-token ids rotate on every refresh, so a single
 *   session cannot be targeted. Instead this revokes all of the user's
 *   refresh tokens and bumps `user.last_updated_password_at`, which core's
 *   SymfonyBearerTokenValidator already uses to reject any access token
 *   issued before it (the same mechanism a password change uses). The user's
 *   password itself is untouched.
 */
class Sw6OidcSessionDestructionService
{
    public function __construct(
        private readonly SalesChannelContextPersister $contextPersister,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly Connection $connection,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function destroy(Sw6OidcSession $session): void
    {
        if ($session->userType === Sw6OidcSession::USER_TYPE_ADMIN) {
            $this->destroyAdminSessions($session->userId);
        } else {
            $this->destroyCustomerSession($session->sessionKey, $session->salesChannelId ?? '', $session->userId);
        }

        $this->logger->info('sw6oidc: local session destroyed.', [
            'userType' => $session->userType,
            'userId' => $session->userId,
            'providerId' => $session->providerId,
        ]);
    }

    /**
     * Ends every session of the account, OIDC or not (forced logout of a
     * session the registry doesn't know, e.g. a Passkey login).
     */
    public function destroyAllForUser(string $userType, string $userId): void
    {
        if ($userType === Sw6OidcSession::USER_TYPE_ADMIN) {
            $this->destroyAdminSessions($userId);

            return;
        }

        $this->contextPersister->revokeAllCustomerTokens($userId);
    }

    private function destroyCustomerSession(string $contextToken, string $salesChannelId, ?string $customerId = null): void
    {
        $known = $this->connection->fetchOne(
            'SELECT 1 FROM `sales_channel_api_context` WHERE `token` = :token',
            ['token' => $contextToken],
        ) !== false;

        if (!$known && $customerId !== null) {
            // Core rotated the token since the login (e.g. a password change):
            // the registered one is gone, but the session lives on under the
            // new token, which can't be targeted — end all of them (R3-L30).
            $this->contextPersister->revokeAllCustomerTokens($customerId);

            return;
        }

        $this->contextPersister->delete($contextToken, $salesChannelId, $customerId);
    }

    public function destroyAdminSessions(string $userId): void
    {
        $this->refreshTokenRepository->revokeRefreshTokensForUser($userId);

        $this->connection->executeStatement(
            'UPDATE `user` SET `last_updated_password_at` = :now WHERE `id` = :id',
            [
                'now' => (new \DateTimeImmutable())->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                'id' => Uuid::fromHexToBytes($userId),
            ],
        );
    }
}
