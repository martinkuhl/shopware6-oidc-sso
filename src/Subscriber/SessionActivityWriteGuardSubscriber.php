<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * The session-activity log is an audit trail: its fields are
 * WriteProtected(system), and this refuses deletes outside system scope,
 * which WriteProtected doesn't cover (N-M8). Retention and account deletion
 * remove rows via DBAL.
 */
class SessionActivityWriteGuardSubscriber implements EventSubscriberInterface
{
    public const CODE_AUDIT_LOG_READ_ONLY = 'SW6OIDC_AUDIT_LOG_READ_ONLY';

    public static function getSubscribedEvents(): array
    {
        return [PreWriteValidationEvent::class => 'validate'];
    }

    public function validate(PreWriteValidationEvent $event): void
    {
        if ($event->getContext()->getScope() === Context::SYSTEM_SCOPE) {
            return;
        }

        foreach ($event->getCommands() as $command) {
            if (!$command instanceof DeleteCommand || $command->getEntityName() !== Sw6OidcSessionActivityDefinition::ENTITY_NAME) {
                continue;
            }

            $message = 'Session activity is an audit log and cannot be deleted through the API.';
            $event->getExceptions()->add(new WriteConstraintViolationException(
                new ConstraintViolationList([new ConstraintViolation($message, $message, [], null, '/', null, null, self::CODE_AUDIT_LOG_READ_ONLY)]),
                $command->getPath(),
            ));
        }
    }
}
