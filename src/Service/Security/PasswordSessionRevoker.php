<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;

/**
 * When SSO-only mode is switched on, sessions that were started with a
 * password would otherwise keep renewing (admin refresh tokens, customer
 * context tokens). This ends the sessions of every account without an SSO
 * binding — they can only have logged in with a password. Bound accounts
 * keep their sessions: they may well be SSO sessions. Guest checkouts stay
 * untouched: they are explicitly allowed in SSO-only mode (R3-M21).
 *
 * Runs from the message queue (PasswordSessionRevocationMessage).
 */
class PasswordSessionRevoker
{
    private const BATCH_SIZE = 500;

    public function __construct(
        private readonly Connection $connection,
        private readonly SsoOnlyInvariant $invariant,
        private readonly Sw6OidcSessionDestructionService $destructionService,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function revokeUnboundAdminSessions(): void
    {
        $userIds = $this->invariant->unboundActiveAdminIds();

        foreach ($userIds as $userId) {
            $this->destructionService->destroyAdminSessions($userId);
        }

        $this->logger->warning('sw6oidc: Administration password login disabled; ended the sessions of admins without SSO binding.', [
            'count' => \count($userIds),
        ]);
    }

    public function revokeUnboundCustomerSessions(): void
    {
        // Same effect as SalesChannelContextPersister::revokeAllCustomerTokens(), in batches.
        $payload = json_encode(['customerId' => null, 'billingAddressId' => null, 'shippingAddressId' => null], JSON_THROW_ON_ERROR);
        $count = 0;

        do {
            /** @var list<string> $tokens */
            $tokens = $this->connection->fetchFirstColumn(
                <<<'SQL'
                    SELECT context.`token`
                    FROM `sales_channel_api_context` context
                    INNER JOIN `customer` ON customer.`id` = context.`customer_id`
                    WHERE customer.`guest` = 0
                      AND NOT EXISTS (
                          SELECT 1 FROM `sw6oidc_user_provider` binding
                          WHERE binding.`user_type` = 'customer' AND binding.`user_id` = customer.`id`
                      )
                    LIMIT :limit
                SQL,
                ['limit' => self::BATCH_SIZE],
                ['limit' => ParameterType::INTEGER],
            );

            if ($tokens === []) {
                break;
            }

            $count += (int) $this->connection->executeStatement(
                'UPDATE `sales_channel_api_context` SET `payload` = :payload, `customer_id` = NULL, `updated_at` = :now WHERE `token` IN (:tokens)',
                [
                    'payload' => $payload,
                    'now' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(Defaults::STORAGE_DATE_TIME_FORMAT),
                    'tokens' => $tokens,
                ],
                ['tokens' => ArrayParameterType::STRING],
            );
        } while (\count($tokens) === self::BATCH_SIZE);

        $this->logger->warning('sw6oidc: customer password login disabled; ended the sessions of customers without SSO binding.', [
            'count' => $count,
        ]);
    }
}
