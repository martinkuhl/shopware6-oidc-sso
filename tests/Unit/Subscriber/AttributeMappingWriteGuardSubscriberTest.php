<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Subscriber\AttributeMappingWriteGuardSubscriber;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSsoSchema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;

#[CoversClass(AttributeMappingWriteGuardSubscriber::class)]
final class AttributeMappingWriteGuardSubscriberTest extends TestCase
{
    private SqliteSsoSchema $db;

    private string $provider;

    protected function setUp(): void
    {
        $this->db = new SqliteSsoSchema();
        $this->provider = $this->db->provider(['require_email_verified' => 0]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, list<string>}>
     */
    public static function payloads(): iterable
    {
        yield 'valid pattern' => [['transform_function' => 'regex_replace', 'transform_params' => '{"pattern":"/^(.*)@corp\\\\.example$/","replacement":"$1"}'], []];
        yield 'missing delimiters' => [['transform_function' => 'regex_replace', 'transform_params' => '{"pattern":"^(.*)$"}'], [AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN]];
        yield 'unbalanced group' => [['transform_function' => 'regex_replace', 'transform_params' => '{"pattern":"/(abc/"}'], [AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN]];
        yield 'empty pattern' => [['transform_function' => 'regex_replace', 'transform_params' => '{"pattern":""}'], [AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN]];
        yield 'no params at all' => [['transform_function' => 'regex_replace'], [AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN]];
        yield 'other function' => [['transform_function' => 'prefix', 'transform_params' => '{"value":"x"}'], []];
    }

    /**
     * @param array<string, mixed> $payload
     * @param list<string>         $codes
     */
    #[DataProvider('payloads')]
    public function testPatternsAreValidatedOnInsert(array $payload, array $codes): void
    {
        self::assertSame($codes, $this->codes($this->insert(['attribute_type' => 'firstname', 'attribute_name' => 'given_name', ...$payload])));
    }

    /**
     * R3-M24: an update only carries the changed columns; the stored row
     * counts as well.
     */
    public function testPartialUpdatesAreValidatedOnTheMergedRow(): void
    {
        $regex = $this->db->attributeMapping($this->provider, ['attribute_type' => 'username', 'attribute_name' => 'preferred_username', 'transform_function' => 'regex_replace', 'transform_params' => '{"pattern":"/^(.*)$/"}']);
        $plain = $this->db->attributeMapping($this->provider, ['attribute_type' => 'username', 'attribute_name' => 'preferred_username', 'transform_params' => '{"pattern":"^(.*)$"}']);

        self::assertSame([AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN], $this->codes($this->update($regex, ['transform_params' => '{"pattern":"(broken"}'])));
        self::assertSame([AttributeMappingWriteGuardSubscriber::CODE_INVALID_PATTERN], $this->codes($this->update($plain, ['transform_function' => 'regex_replace'])));
        self::assertSame([], $this->codes($this->update($regex, ['transform_params' => '{"pattern":"/^(.+)$/"}'])));
    }

    /**
     * R3-M15: with a verified email required, only the untransformed `email`
     * claim can ever count as verified.
     */
    public function testEmailMustStayVerifiableWhileVerificationIsRequired(): void
    {
        $strict = $this->db->provider();

        $transformed = ['attribute_type' => 'email', 'attribute_name' => 'email', 'transform_function' => 'prefix', 'transform_params' => '{"value":"x"}', 'provider_id' => Uuid::fromHexToBytes($strict)];
        $customClaim = ['attribute_type' => 'email', 'attribute_name' => 'mail', 'provider_id' => Uuid::fromHexToBytes($strict)];
        $plain = ['attribute_type' => 'email', 'attribute_name' => 'email', 'provider_id' => Uuid::fromHexToBytes($strict)];

        self::assertSame([AttributeMappingWriteGuardSubscriber::CODE_EMAIL_UNVERIFIABLE], $this->codes($this->insert($transformed)));
        self::assertSame([AttributeMappingWriteGuardSubscriber::CODE_EMAIL_UNVERIFIABLE], $this->codes($this->insert($customClaim)));
        self::assertSame([], $this->codes($this->insert($plain)));

        // The provider's own setting decides, also when it changes in the same write.
        self::assertSame([], $this->codes($this->insert([...$transformed, 'provider_id' => Uuid::fromHexToBytes($this->provider)])));
        self::assertSame([], $this->codes($this->insert($transformed), $this->providerCommand($strict, ['require_email_verified' => 0])));
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function insert(array $payload): WriteCommand
    {
        return $this->command(InsertCommand::class, Sw6OidcAttributeMappingDefinition::ENTITY_NAME, Uuid::randomHex(), ['provider_id' => Uuid::fromHexToBytes($this->provider), ...$payload]);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function update(string $id, array $payload): WriteCommand
    {
        return $this->command(UpdateCommand::class, Sw6OidcAttributeMappingDefinition::ENTITY_NAME, $id, $payload);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function providerCommand(string $id, array $payload): WriteCommand
    {
        return $this->command(UpdateCommand::class, Sw6OidcProviderDefinition::ENTITY_NAME, $id, $payload);
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
     * @return list<string>
     */
    private function codes(WriteCommand ...$commands): array
    {
        $event = new PreWriteValidationEvent(WriteContext::createFromContext(Context::createDefaultContext()), $commands);
        (new AttributeMappingWriteGuardSubscriber($this->db->connection))->validate($event);

        $codes = [];

        foreach ($event->getExceptions()->getExceptions() as $exception) {
            self::assertInstanceOf(WriteConstraintViolationException::class, $exception);

            foreach ($exception->getViolations() as $violation) {
                $codes[] = (string) $violation->getCode();
            }
        }

        return $codes;
    }
}
