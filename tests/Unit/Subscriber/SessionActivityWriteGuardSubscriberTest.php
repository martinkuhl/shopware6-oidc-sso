<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\SessionActivity\Sw6OidcSessionActivityDefinition;
use MartinKuhl\Sw6Oidc\Subscriber\SessionActivityWriteGuardSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Api\Context\SystemSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;

#[CoversClass(SessionActivityWriteGuardSubscriber::class)]
final class SessionActivityWriteGuardSubscriberTest extends TestCase
{
    public function testApiDeletesAreRefused(): void
    {
        $event = $this->event(new Context(new AdminApiSource('0190a1b2c3d4e5f60718293a4b5c6d7e')));

        (new SessionActivityWriteGuardSubscriber())->validate($event);

        self::assertCount(1, $event->getExceptions()->getExceptions());
    }

    public function testSystemScopeMayDelete(): void
    {
        $event = $this->event(new Context(new SystemSource()));

        (new SessionActivityWriteGuardSubscriber())->validate($event);

        self::assertCount(0, $event->getExceptions()->getExceptions());
    }

    private function event(Context $context): PreWriteValidationEvent
    {
        $command = $this->createMock(DeleteCommand::class);
        $command->method('getEntityName')->willReturn(Sw6OidcSessionActivityDefinition::ENTITY_NAME);
        $command->method('getPath')->willReturn('/0');

        return new PreWriteValidationEvent(WriteContext::createFromContext($context), [$command]);
    }
}
