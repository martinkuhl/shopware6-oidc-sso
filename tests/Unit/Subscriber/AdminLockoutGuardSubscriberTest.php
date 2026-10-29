<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Subscriber\AdminLockoutGuardSubscriber;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSsoSchema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\User\UserDefinition;

#[CoversClass(AdminLockoutGuardSubscriber::class)]
final class AdminLockoutGuardSubscriberTest extends TestCase
{
    private SqliteSsoSchema $db;

    private string $admin;

    protected function setUp(): void
    {
        $this->db = new SqliteSsoSchema();
        $provider = $this->db->provider(['disable_non_oidc_admin_login' => 1]);
        $this->admin = $this->db->admin();
        $this->db->bind($provider, $this->admin);
    }

    public function testDeletingTheLastSsoAdminIsRefusedUnderSsoOnlyMode(): void
    {
        self::assertCount(1, $this->validate($this->command(DeleteCommand::class, [])));
    }

    public function testDeactivatingTheLastSsoAdminIsRefusedUnderSsoOnlyMode(): void
    {
        self::assertCount(1, $this->validate($this->command(UpdateCommand::class, ['active' => 0])));
    }

    public function testOtherAdminsKeepAccess(): void
    {
        $this->db->bind($this->db->provider(), $this->db->admin());

        self::assertCount(0, $this->validate($this->command(DeleteCommand::class, [])));
    }

    public function testInactiveOtherAdminsDoNotCount(): void
    {
        $this->db->bind($this->db->provider(), $this->db->admin(active: false));

        self::assertCount(1, $this->validate($this->command(DeleteCommand::class, [])));
    }

    public function testNothingIsCheckedWithoutSsoOnlyMode(): void
    {
        $this->db->connection->executeStatement('UPDATE `sw6oidc_provider` SET `disable_non_oidc_admin_login` = 0');

        self::assertCount(0, $this->validate($this->command(DeleteCommand::class, [])));
    }

    public function testUnrelatedUpdatesPass(): void
    {
        self::assertCount(0, $this->validate($this->command(UpdateCommand::class, ['first_name' => 'x'])));
    }

    /**
     * @return array<\Throwable>
     */
    private function validate(WriteCommand $command): array
    {
        $event = new PreWriteValidationEvent(WriteContext::createFromContext(Context::createDefaultContext()), [$command]);
        (new AdminLockoutGuardSubscriber(new SsoOnlyInvariant($this->db->connection)))->validate($event);

        return $event->getExceptions()->getExceptions();
    }

    /**
     * @param class-string<WriteCommand> $class
     * @param array<string, mixed>       $payload
     */
    private function command(string $class, array $payload): WriteCommand
    {
        $command = $this->createStub($class);
        $command->method('getEntityName')->willReturn(UserDefinition::ENTITY_NAME);
        $command->method('getPayload')->willReturn($payload);
        $command->method('getPrimaryKey')->willReturn(['id' => Uuid::fromHexToBytes($this->admin)]);
        $command->method('getPath')->willReturn('/0');

        return $command;
    }
}
