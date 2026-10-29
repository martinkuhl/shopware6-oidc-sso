<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialDefinition;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeySessionTerminator;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityDeletedEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Whatever deletes a passkey (the owner on the Storefront or in the
 * Administration profile, an admin in the recovery grid), the sessions it
 * logged in end once the delete is committed (R3-M6). The credential is
 * gone by then, so its owner and hash are remembered before the write.
 */
class PasskeyDeletionSubscriber implements EventSubscriberInterface, ResetInterface
{
    /** @var array<string, array{user_type: string, user_id: string, credential_id_hash: string}> credential id (hex) => row */
    private array $pending = [];

    /** @var array<string, bool> user id (hex) => whether sessions were ended, for the current request */
    private array $ended = [];

    public function __construct(
        private readonly Connection $connection,
        private readonly PasskeySessionTerminator $terminator,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            PreWriteValidationEvent::class => 'rememberDeletedCredentials',
            Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME . '.deleted' => 'onDeleted',
        ];
    }

    public function rememberDeletedCredentials(PreWriteValidationEvent $event): void
    {
        foreach ($event->getCommandsForEntity(Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME) as $command) {
            $id = $command->getPrimaryKey()['id'] ?? null;

            if (!$command instanceof DeleteCommand || !\is_string($id)) {
                continue;
            }

            $row = $this->connection->fetchAssociative(
                'SELECT `user_type`, LOWER(HEX(`user_id`)) AS `user_id`, `credential_id_hash` FROM `sw6oidc_passkey_credential` WHERE `id` = :id',
                ['id' => $id],
            );

            if (\is_array($row)) {
                /** @var array{user_type: string, user_id: string, credential_id_hash: string} $row */
                $this->pending[Uuid::fromBytesToHex($id)] = $row;
            }
        }
    }

    public function onDeleted(EntityDeletedEvent $event): void
    {
        foreach ($event->getIds() as $id) {
            if (!\is_string($id) || !isset($this->pending[$id])) {
                continue;
            }

            $row = $this->pending[$id];
            unset($this->pending[$id]);

            if ($this->terminator->endSessionsOf($row['user_type'], $row['user_id'], $row['credential_id_hash'])) {
                $this->ended[$row['user_id']] = true;
            }
        }
    }

    /**
     * Whether deleting a passkey in this request ended sessions of that
     * user (the admin's own session included: the Administration then logs
     * itself out).
     */
    public function endedSessionsOf(string $userId): bool
    {
        return $this->ended[$userId] ?? false;
    }

    public function reset(): void
    {
        $this->pending = [];
        $this->ended = [];
    }
}
