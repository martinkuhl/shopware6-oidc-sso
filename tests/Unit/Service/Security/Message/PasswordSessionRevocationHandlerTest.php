<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security\Message;

use MartinKuhl\Sw6Oidc\Service\Security\Message\PasswordSessionRevocationHandler;
use MartinKuhl\Sw6Oidc\Service\Security\Message\PasswordSessionRevocationMessage;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordLoginPolicy;
use MartinKuhl\Sw6Oidc\Service\Security\PasswordSessionRevoker;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

#[CoversClass(PasswordSessionRevocationHandler::class)]
final class PasswordSessionRevocationHandlerTest extends TestCase
{
    /**
     * R8-M7: the queued message may outlive the write that queued it (a
     * rolled-back dry run, password login switched on again).
     */
    public function testNothingIsRevokedOncePasswordLoginIsAllowedAgain(): void
    {
        $revoker = $this->createMock(PasswordSessionRevoker::class);
        $revoker->expects(self::never())->method('revokeUnboundAdminSessions');

        (new PasswordSessionRevocationHandler($revoker, $this->policy(false), new NullLogger()))(new PasswordSessionRevocationMessage('admin'));
    }

    public function testUnboundSessionsAreRevokedWhilePasswordLoginIsOff(): void
    {
        $revoker = $this->createMock(PasswordSessionRevoker::class);
        $revoker->expects(self::once())->method('revokeUnboundCustomerSessions');

        (new PasswordSessionRevocationHandler($revoker, $this->policy(true), new NullLogger()))(new PasswordSessionRevocationMessage('customer'));
    }

    private function policy(bool $disabled): PasswordLoginPolicy
    {
        $policy = $this->createStub(PasswordLoginPolicy::class);
        $policy->method('isPasswordLoginDisabled')->willReturn($disabled);

        return $policy;
    }
}
