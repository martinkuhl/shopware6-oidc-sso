<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderDefinition;
use MartinKuhl\Sw6Oidc\Subscriber\TrustEntityWriteGuardSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;

/**
 * R3-H2/R3-H3: the Admin API can't plant passkeys or bindings, nor delete
 * bindings. Field-level changes are blocked by WriteProtected(system).
 */
#[CoversClass(TrustEntityWriteGuardSubscriber::class)]
final class TrustEntityWriteGuardSubscriberTest extends TestCase
{
    /**
     * @return iterable<string, array{string, class-string<WriteCommand>, bool}>
     */
    public static function commands(): iterable
    {
        yield 'passkey insert' => [Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME, InsertCommand::class, true];
        yield 'passkey update (nickname; other fields are write-protected)' => [Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME, UpdateCommand::class, false];
        yield 'passkey delete (recovery grid)' => [Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME, DeleteCommand::class, false];
        yield 'binding insert' => [Sw6OidcUserProviderDefinition::ENTITY_NAME, InsertCommand::class, true];
        yield 'binding delete' => [Sw6OidcUserProviderDefinition::ENTITY_NAME, DeleteCommand::class, true];
        yield 'other entity' => ['product', InsertCommand::class, false];
    }

    /**
     * @param class-string<WriteCommand> $class
     */
    #[DataProvider('commands')]
    public function testAdminApiWrites(string $entity, string $class, bool $refused): void
    {
        self::assertCount($refused ? 1 : 0, $this->validate($entity, $class, new Context(new AdminApiSource(null))));
    }

    /**
     * @param class-string<WriteCommand> $class
     */
    #[DataProvider('commands')]
    public function testSystemScopeMayWriteEverything(string $entity, string $class): void
    {
        self::assertCount(0, $this->validate($entity, $class, Context::createDefaultContext()));
    }

    /**
     * @param class-string<WriteCommand> $class
     *
     * @return array<\Throwable>
     */
    private function validate(string $entity, string $class, Context $context): array
    {
        $command = $this->createStub($class);
        $command->method('getEntityName')->willReturn($entity);
        $command->method('getPath')->willReturn('/0');

        $event = new PreWriteValidationEvent(WriteContext::createFromContext($context), [$command]);
        (new TrustEntityWriteGuardSubscriber())->validate($event);

        return $event->getExceptions()->getExceptions();
    }
}
