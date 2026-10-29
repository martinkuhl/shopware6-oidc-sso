<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionDestructionService;
use MartinKuhl\Sw6Oidc\Service\Session\Sw6OidcSessionRegistry;
use Psr\Log\LoggerInterface;
use Shopware\Core\Checkout\Customer\CustomerEvents;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityDeletedEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\User\UserEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * The plugin's per-account rows are polymorphic (`user_type`, `user_id`)
 * without foreign keys, so nothing cascades when an account goes away:
 *
 * - **deleted** user/customer: the IdP binding, passkeys, session registry
 *   entries and session-activity rows (IP, user agent, `sub`) are removed
 *   (M15, N-L12 — no personal data outliving the account);
 * - **deactivated** user/customer: every session is ended, so a deactivated
 *   account can't keep using a token or context it already holds (M15).
 */
class UserProviderCleanupSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly UserProviderBindingService $bindingService,
        private readonly Connection $connection,
        private readonly Sw6OidcSessionRegistry $sessionRegistry,
        private readonly Sw6OidcSessionDestructionService $destructionService,
        private readonly LoggerInterface $logger,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            UserEvents::USER_DELETED_EVENT => 'onUserDeleted',
            CustomerEvents::CUSTOMER_DELETED_EVENT => 'onCustomerDeleted',
            UserEvents::USER_WRITTEN_EVENT => 'onUserWritten',
            CustomerEvents::CUSTOMER_WRITTEN_EVENT => 'onCustomerWritten',
        ];
    }

    public function onUserDeleted(EntityDeletedEvent $event): void
    {
        $this->cleanUp(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $event);
    }

    public function onCustomerDeleted(EntityDeletedEvent $event): void
    {
        $this->cleanUp(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $event);
    }

    public function onUserWritten(EntityWrittenEvent $event): void
    {
        $this->endSessionsOfDeactivated(Sw6OidcUserProviderEntity::USER_TYPE_ADMIN, $event);
    }

    public function onCustomerWritten(EntityWrittenEvent $event): void
    {
        $this->endSessionsOfDeactivated(Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER, $event);
    }

    private function cleanUp(string $userType, EntityDeletedEvent $event): void
    {
        $event->getContext()->scope(Context::SYSTEM_SCOPE, function (Context $context) use ($userType, $event): void {
            foreach ($event->getIds() as $id) {
                if (!\is_string($id)) {
                    continue;
                }

                $this->bindingService->unbind($userType, $id, $context);
                $this->sessionRegistry->removeAllForUser($userType, $id);

                foreach (['sw6oidc_passkey_credential', 'sw6oidc_session_activity'] as $table) {
                    $this->connection->executeStatement(
                        sprintf('DELETE FROM `%s` WHERE `user_type` = :userType AND `user_id` = :userId', $table),
                        ['userType' => $userType, 'userId' => Uuid::fromHexToBytes($id)],
                    );
                }
            }
        });
    }

    private function endSessionsOfDeactivated(string $userType, EntityWrittenEvent $event): void
    {
        foreach ($event->getWriteResults() as $result) {
            $id = $result->getPrimaryKey();

            if (!\is_string($id) || !$result->hasPayload('active') || $result->getProperty('active') !== false) {
                continue;
            }

            try {
                $this->destructionService->destroyAllForUser($userType, $id);
                $this->sessionRegistry->removeAllForUser($userType, $id);
            } catch (\Throwable $exception) {
                // Deactivation itself must not fail because of this.
                $this->logger->error('sw6oidc: could not end the sessions of a deactivated account.', [
                    'userType' => $userType,
                    'userId' => $id,
                    'exceptionClass' => $exception::class,
                ]);
            }
        }
    }
}
