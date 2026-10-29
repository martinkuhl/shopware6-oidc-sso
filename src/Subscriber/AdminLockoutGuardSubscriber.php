<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Shopware\Core\System\User\UserDefinition;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * While Administration password login is disabled, refuses deleting or
 * deactivating the last admin who could still log in through SSO — that
 * would leave nobody able to log in (break-glass:
 * SW6OIDC_ALLOW_PASSWORD_LOGIN=1, which also turns the policy off). One of
 * the callers of the SSO-only invariant (R3-H7).
 */
class AdminLockoutGuardSubscriber implements EventSubscriberInterface
{
    public const CODE_LAST_SSO_ADMIN = 'SW6OIDC_LAST_SSO_ADMIN';

    public function __construct(private readonly SsoOnlyInvariant $invariant)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [PreWriteValidationEvent::class => 'validate'];
    }

    public function validate(PreWriteValidationEvent $event): void
    {
        $removedUserIds = [];
        $commands = [];

        foreach ($event->getCommandsForEntity(UserDefinition::ENTITY_NAME) as $command) {
            $userId = $command->getPrimaryKey()['id'] ?? null;

            if (!\is_string($userId)) {
                continue;
            }

            $deactivates = $command instanceof UpdateCommand
                && \array_key_exists('active', $command->getPayload())
                && !$command->getPayload()['active'];

            if ($command instanceof DeleteCommand || $deactivates) {
                $removedUserIds[] = Uuid::fromBytesToHex($userId);
                $commands[] = $command;
            }
        }

        if ($removedUserIds === [] || $this->invariant->holds(removedUserIds: $removedUserIds) || !$this->invariant->holds()) {
            return;
        }

        $message = 'Administration password login is disabled and this is the last admin who can log in through single sign-on.';

        foreach ($commands as $command) {
            $violations = new ConstraintViolationList([
                new ConstraintViolation($message, $message, [], null, '/active', false, null, self::CODE_LAST_SSO_ADMIN),
            ]);
            $event->getExceptions()->add(new WriteConstraintViolationException($violations, $command->getPath()));
        }
    }
}
