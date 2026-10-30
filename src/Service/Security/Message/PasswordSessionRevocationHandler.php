<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Message;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordSessionRevoker;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Ends the password sessions of unbound accounts once password login was
 * switched off. The policy is checked again when the message runs: it may
 * have been switched back on meanwhile, or the write that queued it was
 * rolled back (a dry-run import with a non-database transport, R8-M7).
 */
#[AsMessageHandler]
final readonly class PasswordSessionRevocationHandler
{
    public function __construct(
        private PasswordSessionRevoker $revoker,
        private PasswordLoginPolicy $passwordLoginPolicy,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(PasswordSessionRevocationMessage $message): void
    {
        if (!$this->passwordLoginPolicy->isPasswordLoginDisabled($message->userType, Context::createDefaultContext())) {
            $this->logger->info('sw6oidc: password-session revocation skipped, password login is allowed again.', ['userType' => $message->userType]);

            return;
        }

        match ($message->userType) {
            LoginType::Admin->value => $this->revoker->revokeUnboundAdminSessions(),
            LoginType::Customer->value => $this->revoker->revokeUnboundCustomerSessions(),
            default => null,
        };
    }
}
