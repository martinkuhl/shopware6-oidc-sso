<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security\Message;

use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordSessionRevoker;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final readonly class PasswordSessionRevocationHandler
{
    public function __construct(private PasswordSessionRevoker $revoker)
    {
    }

    public function __invoke(PasswordSessionRevocationMessage $message): void
    {
        match ($message->userType) {
            LoginType::Admin->value => $this->revoker->revokeUnboundAdminSessions(),
            LoginType::Customer->value => $this->revoker->revokeUnboundCustomerSessions(),
            default => null,
        };
    }
}
