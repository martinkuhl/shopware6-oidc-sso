<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * Passkey credentials and account bindings decide which account a login
 * resolves to. Their fields are WriteProtected(system) (R3-H2, R3-H3); this
 * covers what that flag doesn't:
 *
 * - no insert outside system scope, so nobody can plant a passkey or a
 *   binding for another account through the Admin or Sync API;
 * - no binding delete outside system scope: unlinking goes through
 *   OidcUserProviderAdminController, which checks the SSO-only invariant.
 *
 * Deleting a passkey through the API stays possible (the recovery grid): it
 * removes access, it never grants any.
 */
class TrustEntityWriteGuardSubscriber implements EventSubscriberInterface
{
    public const CODE_TRUST_DATA_READ_ONLY = 'SW6OIDC_TRUST_DATA_READ_ONLY';

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
            if (!$this->isRefused($command)) {
                continue;
            }

            $message = \sprintf('"%s" can only be written by the plugin itself.', $command->getEntityName());
            $event->getExceptions()->add(new WriteConstraintViolationException(
                new ConstraintViolationList([new ConstraintViolation($message, $message, [], null, '/', null, null, self::CODE_TRUST_DATA_READ_ONLY)]),
                $command->getPath(),
            ));
        }
    }

    private function isRefused(WriteCommand $command): bool
    {
        return match ($command->getEntityName()) {
            Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME => $command instanceof InsertCommand,
            Sw6OidcUserProviderDefinition::ENTITY_NAME => $command instanceof InsertCommand || $command instanceof DeleteCommand,
            default => false,
        };
    }
}
