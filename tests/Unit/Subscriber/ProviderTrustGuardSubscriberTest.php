<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingDefinition;
use MartinKuhl\Sw6Oidc\Subscriber\ProviderTrustGuardSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;

/**
 * R3-H4: whoever controls a provider's endpoints, scope or superadmin
 * mapping can log in as any bound account, so only superadmins may.
 */
#[CoversClass(ProviderTrustGuardSubscriber::class)]
final class ProviderTrustGuardSubscriberTest extends TestCase
{
    private Connection $connection;

    private string $adminProvider;

    private string $customerProvider;

    /** @var list<array{string, array<string, mixed>}> */
    private array $logged = [];

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $columns = implode(', ', array_map(static fn (string $column): string => \sprintf('`%s` TEXT NULL', $column), array_keys(ProviderTrustGuardSubscriber::TRUST_FIELDS)));
        $this->connection->executeStatement(\sprintf('CREATE TABLE `sw6oidc_provider` (`id` BLOB PRIMARY KEY, %s)', $columns));
        $this->connection->executeStatement('CREATE TABLE `sw6oidc_role_mapping` (`id` BLOB PRIMARY KEY, `provider_id` BLOB, `mapping_type` TEXT)');
        $this->connection->executeStatement('CREATE TABLE `sw6oidc_attribute_mapping` (`id` BLOB PRIMARY KEY, `provider_id` BLOB, `attribute_type` TEXT)');
        $this->connection->executeStatement('CREATE TABLE `sw6oidc_access_control_rule` (`id` BLOB PRIMARY KEY, `provider_id` BLOB)');

        $this->adminProvider = $this->provider(['login_type' => 'both', 'access_token_endpoint' => 'https://idp.example/token', 'base64_claims' => '["groups", "roles"]']);
        $this->customerProvider = $this->provider(['login_type' => 'customer']);
    }

    public function testEditorCannotChangeTrustFields(): void
    {
        $exceptions = $this->validate([$this->command(UpdateCommand::class, Sw6OidcProviderDefinition::ENTITY_NAME, $this->adminProvider, [
            'access_token_endpoint' => 'https://evil.example/token',
            'scope' => 'profile',
            'display_name' => 'renamed',
        ])], $this->editor());

        self::assertSame(['/accessTokenEndpoint', '/scope'], $this->paths($exceptions));
    }

    public function testEditorCanChangeEverythingElseAndResendUnchangedValues(): void
    {
        self::assertSame([], $this->paths($this->validate([$this->command(UpdateCommand::class, Sw6OidcProviderDefinition::ENTITY_NAME, $this->adminProvider, [
            'display_name' => 'renamed',
            'access_token_endpoint' => 'https://idp.example/token',
            'base64_claims' => '["groups","roles"]',
        ])], $this->editor())));
        self::assertSame([], $this->logged);
    }

    public function testEditorCannotCreateProviders(): void
    {
        $exceptions = $this->validate([$this->command(InsertCommand::class, Sw6OidcProviderDefinition::ENTITY_NAME, Uuid::randomHex(), ['client_id' => 'x'])], $this->editor());

        self::assertSame(['/clientId'], $this->paths($exceptions));
    }

    public function testSuperadminSystemScopeAndAdminIntegrationsMayChangeThemAndAreAudited(): void
    {
        $superadmin = new AdminApiSource(Uuid::randomHex());
        $superadmin->setIsAdmin(true);

        foreach ([new Context($superadmin), Context::createDefaultContext()] as $context) {
            self::assertSame([], $this->paths($this->validate([$this->command(UpdateCommand::class, Sw6OidcProviderDefinition::ENTITY_NAME, $this->adminProvider, [
                'access_token_endpoint' => 'https://new.example/token',
            ])], $context)));
        }

        self::assertCount(2, $this->logged);
        self::assertSame(['accessTokenEndpoint' => 'https://new.example/token'], $this->logged[0][1]['changes']);
        self::assertSame($superadmin->getUserId(), $this->logged[0][1]['adminUserId']);
    }

    public function testPrivilegedRoleMappingsNeedASuperadmin(): void
    {
        $role = $this->command(InsertCommand::class, Sw6OidcRoleMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['mapping_type' => 'superadmin']);
        $group = $this->command(InsertCommand::class, Sw6OidcRoleMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['mapping_type' => 'customer_group']);

        self::assertSame(['/mappingType'], $this->paths($this->validate([$role, $group], $this->editor())));

        // Deleting or retyping a stored admin-role row counts as well.
        $stored = Uuid::randomHex();
        $this->connection->insert('sw6oidc_role_mapping', ['id' => Uuid::fromHexToBytes($stored), 'mapping_type' => 'admin_role'], ['id' => ParameterType::BINARY]);
        self::assertSame(['/mappingType'], $this->paths($this->validate([$this->command(DeleteCommand::class, Sw6OidcRoleMappingDefinition::ENTITY_NAME, $stored, [])], $this->editor())));
    }

    public function testIdentityMappingsAndAccessRulesOfAdminProvidersNeedASuperadmin(): void
    {
        $adminEmail = $this->command(InsertCommand::class, Sw6OidcAttributeMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->adminProvider), 'attribute_type' => 'email']);
        $adminName = $this->command(InsertCommand::class, Sw6OidcAttributeMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->adminProvider), 'attribute_type' => 'firstname']);
        $customerEmail = $this->command(InsertCommand::class, Sw6OidcAttributeMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->customerProvider), 'attribute_type' => 'email']);
        $adminRule = $this->command(InsertCommand::class, Sw6OidcAccessControlRuleDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->adminProvider)]);
        $customerRule = $this->command(InsertCommand::class, Sw6OidcAccessControlRuleDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->customerProvider)]);

        self::assertSame(['/attributeType', '/claimKey'], $this->paths($this->validate([$adminEmail, $adminName, $customerEmail, $adminRule, $customerRule], $this->editor())));
    }

    private function editor(): Context
    {
        $source = new AdminApiSource(Uuid::randomHex());
        $source->setPermissions(['sw6oidc_provider:update']);

        return new Context($source);
    }

    /**
     * @param array<string, mixed> $columns
     */
    private function provider(array $columns): string
    {
        $id = Uuid::randomHex();
        $this->connection->insert('sw6oidc_provider', ['id' => Uuid::fromHexToBytes($id), ...$columns], ['id' => ParameterType::BINARY]);

        return $id;
    }

    /**
     * @param list<WriteCommand> $commands
     *
     * @return array<\Throwable>
     */
    private function validate(array $commands, Context $context): array
    {
        $logger = new class($this->logged) extends AbstractLogger {
            /**
             * @param list<array{string, array<string, mixed>}> $logged
             */
            public function __construct(public array &$logged)
            {
            }

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->logged[] = [(string) $message, $context];
            }
        };

        $event = new PreWriteValidationEvent(WriteContext::createFromContext($context), $commands);
        (new ProviderTrustGuardSubscriber($this->connection, $logger))->validate($event);

        return $event->getExceptions()->getExceptions();
    }

    /**
     * @param class-string<WriteCommand> $class
     * @param array<string, mixed>       $payload
     */
    private function command(string $class, string $entity, string $id, array $payload): WriteCommand
    {
        $command = $this->createStub($class);
        $command->method('getEntityName')->willReturn($entity);
        $command->method('getPayload')->willReturn($payload);
        $command->method('getPrimaryKey')->willReturn(['id' => Uuid::fromHexToBytes($id)]);
        $command->method('getPath')->willReturn('/0');

        return $command;
    }

    /**
     * @param array<\Throwable> $exceptions
     *
     * @return list<string>
     */
    private function paths(array $exceptions): array
    {
        $paths = [];

        foreach ($exceptions as $exception) {
            self::assertInstanceOf(WriteConstraintViolationException::class, $exception);

            foreach ($exception->getViolations() as $violation) {
                self::assertSame(ProviderTrustGuardSubscriber::CODE_SUPERADMIN_REQUIRED, $violation->getCode());
                $paths[] = $violation->getPropertyPath();
            }
        }

        return $paths;
    }
}
