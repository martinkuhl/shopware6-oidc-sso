<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderDefinition;
use MartinKuhl\Sw6Oidc\Service\Security\IssuerChangeConfirmationStore;
use MartinKuhl\Sw6Oidc\Service\Security\LockoutConfirmationStore;
use MartinKuhl\Sw6Oidc\Service\Security\Message\PasswordSessionRevocationMessage;
use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use MartinKuhl\Sw6Oidc\Subscriber\Sw6OidcProviderWriteGuardSubscriber;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\InMemoryAtomicCache;
use MartinKuhl\Sw6Oidc\Tests\Unit\Support\SqliteSsoSchema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityWriteResult;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\DeleteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\InsertCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\UpdateCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Command\WriteCommand;
use Shopware\Core\Framework\DataAbstractionLayer\Write\Validation\PreWriteValidationEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteContext;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Validator\ConstraintViolationInterface;

#[CoversClass(Sw6OidcProviderWriteGuardSubscriber::class)]
final class Sw6OidcProviderWriteGuardSubscriberTest extends TestCase
{
    private const APP_SECRET = 'test-app-secret';

    private SqliteSsoSchema $db;

    private LockoutConfirmationStore $confirmations;

    private IssuerChangeConfirmationStore $issuerChanges;

    private string $actingAdmin;

    /** @var list<object> */
    private array $dispatched = [];

    private Sw6OidcProviderWriteGuardSubscriber $subscriber;

    protected function setUp(): void
    {
        $this->db = new SqliteSsoSchema();
        $this->confirmations = new LockoutConfirmationStore(new InMemoryAtomicCache());
        $this->issuerChanges = new IssuerChangeConfirmationStore(new InMemoryAtomicCache());
        $this->actingAdmin = Uuid::randomHex();
    }

    public function testEncryptedWebhookUrlIsDecryptedAndSsrfChecked(): void
    {
        $id = $this->db->provider();
        $encrypted = (new Sw6OidcEncryptor(self::APP_SECRET))->encrypt('https://hooks.internal.example/T000/B000/xyz', 'sw6oidc_provider.health_alert_webhook_url');

        $violation = $this->singleViolation($this->validate([$this->update($id, ['health_alert_webhook_url' => $encrypted])], privateIps: true));
        self::assertSame('/healthAlertWebhookUrl', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_URL_BLOCKED, $violation->getCode());

        $this->assertNoViolations($this->validate([$this->update($id, ['health_alert_webhook_url' => $encrypted])]));
    }

    public function testAnExplicitNullBooleanIsAViolationNotADatabaseError(): void
    {
        $violation = $this->singleViolation($this->validate([$this->update($this->db->provider(), ['is_active' => null])]));

        // R3-L43: the NOT NULL column used to turn this into a 500.
        self::assertSame('/isActive', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_VALUE_REQUIRED, $violation->getCode());
    }

    public function testDeletingAProviderWithBindingsNeedsTheConfirmation(): void
    {
        $id = $this->db->provider(['login_type' => 'customer']);
        $this->db->bind($id, $this->db->admin());

        // R3-L43: the bindings go with the provider, so a plain delete is refused.
        self::assertSame(
            Sw6OidcProviderWriteGuardSubscriber::CODE_PROVIDER_HAS_BINDINGS,
            $this->singleViolation($this->validate([$this->delete($id)]))->getCode(),
        );
        $this->assertNoViolations($this->validate([$this->delete($id)], bindingLossConfirmed: true));
        $this->assertNoViolations($this->validate([$this->delete($this->db->provider(['login_type' => 'customer']))]));
    }

    public function testBlockedEndpointAddsFieldScopedViolation(): void
    {
        $violation = $this->singleViolation($this->validate([$this->update($this->db->provider(), ['jwks_endpoint' => 'https://internal.example/jwks'])], privateIps: true));

        self::assertSame('/jwksEndpoint', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_URL_BLOCKED, $violation->getCode());
    }

    public function testPublicEndpointsPass(): void
    {
        $this->assertNoViolations($this->validate([$this->insert([
            'authorize_endpoint' => 'https://idp.example/authorize',
            'access_token_endpoint' => 'https://idp.example/token',
            'well_known_config_url' => 'https://idp.example/.well-known/openid-configuration',
            'client_secret' => 'sw6oidc_v2:new',
        ])]));
    }

    public function testIssuerIsNotValidated(): void
    {
        $this->assertNoViolations($this->validate([$this->update($this->db->provider(), ['issuer' => 'http://127.0.0.1'])], privateIps: true));
    }

    public function testPostLogoutUrlMustBeAnAbsoluteHttpUrl(): void
    {
        $id = $this->db->provider();

        foreach (['javascript:alert(1)', '/account/login', 'data:text/html,x', 'https://'] as $bad) {
            $violation = $this->singleViolation($this->validate([$this->update($id, ['post_logout_url' => $bad])]));
            self::assertSame('/postLogoutUrl', $violation->getPropertyPath(), $bad);
            self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_REDIRECT_URL_INVALID, $violation->getCode());
        }

        $this->assertNoViolations($this->validate([$this->update($id, ['post_logout_url' => 'http://localhost/sw6oidc/postlogout'])], privateIps: true));
    }

    public function testConfidentialClientNeedsASecretOnInsert(): void
    {
        $violation = $this->singleViolation($this->validate([$this->insert(['client_id' => 'shop'])]));

        self::assertSame('/clientSecret', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_CLIENT_SECRET_REQUIRED, $violation->getCode());
    }

    public function testPublicClientNeedsNoSecret(): void
    {
        $this->assertNoViolations($this->validate([$this->insert(['client_id' => 'spa', 'public_client' => 1])]));
    }

    public function testChangingATokenUrlNeedsTheSecretAgain(): void
    {
        $id = $this->db->provider(['access_token_endpoint' => 'https://idp.example/token']);

        $violation = $this->singleViolation($this->validate([$this->update($id, ['access_token_endpoint' => 'https://evil.example/token'])]));
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_SECRET_REQUIRED, $violation->getCode());
        self::assertSame('/clientSecret', $violation->getPropertyPath());

        $this->assertNoViolations($this->validate([$this->update($id, ['access_token_endpoint' => 'https://evil.example/token', 'client_secret' => 'sw6oidc_v2:new'])]));
    }

    public function testSeveralChangedCredentialUrlsGiveOneViolationOnTheSecret(): void
    {
        $id = $this->db->provider(['access_token_endpoint' => 'https://idp.example/token']);

        $violation = $this->singleViolation($this->validate([$this->update($id, [
            'access_token_endpoint' => 'https://idp2.example/token',
            'user_info_endpoint' => 'https://idp2.example/userinfo',
            'revocation_endpoint' => 'https://idp2.example/revoke',
            'well_known_config_url' => 'https://idp2.example/.well-known/openid-configuration',
        ])]));

        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_SECRET_REQUIRED, $violation->getCode());
        self::assertSame('/clientSecret', $violation->getPropertyPath());
        self::assertSame(['accessTokenEndpoint', 'revocationEndpoint', 'userInfoEndpoint', 'wellKnownConfigUrl'], $violation->getInvalidValue());
    }

    /**
     * R3-M4: `{publicClient: true, endpoint: evil}` then `{publicClient: false}`.
     */
    public function testPublicClientToggleCannotBypassTheSecretRule(): void
    {
        $id = $this->db->provider(['access_token_endpoint' => 'https://idp.example/token']);

        $first = $this->singleViolation($this->validate([$this->update($id, ['public_client' => 1, 'access_token_endpoint' => 'https://evil.example/token'])]));
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_SECRET_REQUIRED, $first->getCode());

        // Even if the first step had gone through: turning the client confidential needs the secret.
        $this->db->connection->executeStatement('UPDATE `sw6oidc_provider` SET `public_client` = 1');
        $second = $this->singleViolation($this->validate([$this->update($id, ['public_client' => 0])]));
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_CLIENT_SECRET_REQUIRED, $second->getCode());
    }

    public function testEnablingCustomerFlagNeedsABoundCustomer(): void
    {
        $id = $this->db->provider();

        $violation = $this->singleViolation($this->validate([$this->update($id, ['disable_non_oidc_customer_login' => 1])]));
        self::assertSame('/disableNonOidcCustomerLogin', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD, $violation->getCode());

        $this->db->bind($id, Uuid::randomHex(), 'customer');
        $this->assertNoViolations($this->validate([$this->update($id, ['disable_non_oidc_customer_login' => 1])]));
        self::assertEquals([new PasswordSessionRevocationMessage('customer')], $this->written($id));
    }

    public function testEnablingAdminFlagWithoutAnyBoundAdminIsRejected(): void
    {
        $violation = $this->singleViolation($this->validate([$this->update($this->db->provider(), ['disable_non_oidc_admin_login' => 1])]));

        self::assertSame('/disableNonOidcAdminLogin', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD, $violation->getCode());
    }

    public function testInactiveBoundAdminsDoNotCount(): void
    {
        $id = $this->db->provider();
        $this->db->bind($id, $this->db->admin(active: false));

        $violation = $this->singleViolation($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])]));

        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD, $violation->getCode());
    }

    public function testUnboundAdminsNeedAnExplicitConfirmationByTheActingAdmin(): void
    {
        $id = $this->db->provider();
        $this->db->bind($id, $this->db->admin());
        $this->db->admin();
        $this->db->admin();

        $violation = $this->singleViolation($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])]));
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_UNBOUND_USERS, $violation->getCode());
        self::assertStringContainsString('2 active admin', (string) $violation->getMessage());

        // Another admin's confirmation doesn't count (R3-M22).
        $this->confirmations->confirm($id, Uuid::randomHex());
        $this->singleViolation($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])]));

        $this->confirmations->confirm($id, $this->actingAdmin);
        $this->assertNoViolations($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])]));
        self::assertEquals([new PasswordSessionRevocationMessage('admin')], $this->written($id));
    }

    public function testFlagThatIsAlreadyOnIsNotRevalidated(): void
    {
        $id = $this->db->provider(['disable_non_oidc_admin_login' => 1]);

        $this->assertNoViolations($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])]));
        self::assertSame([], $this->written($id));
    }

    public function testFlagNeedsAVisibleSsoButton(): void
    {
        $id = $this->db->provider();
        $this->db->bind($id, Uuid::randomHex(), 'customer');

        $violation = $this->singleViolation($this->validate([$this->update($id, ['disable_non_oidc_customer_login' => 1, 'show_customer_link' => 0])]));

        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_NO_VISIBLE_LOGIN, $violation->getCode());
    }

    /**
     * R3-H7: re-activating a provider that already has the flag, with only
     * an inactive admin bound, used to skip every check.
     */
    public function testReactivatingAFlaggedProviderIsChecked(): void
    {
        $id = $this->db->provider(['disable_non_oidc_admin_login' => 1, 'is_active' => 0]);
        $this->db->bind($id, $this->db->admin(active: false));

        $violation = $this->singleViolation($this->validate([$this->update($id, ['is_active' => 1])]));

        self::assertSame('/disableNonOidcAdminLogin', $violation->getPropertyPath());
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD, $violation->getCode());
    }

    public function testRescopingAFlaggedProviderNeedsConfirmationAndRevokesSessions(): void
    {
        $id = $this->db->provider(['disable_non_oidc_admin_login' => 1, 'login_type' => 'customer']);
        $this->db->bind($id, $this->db->admin());
        $this->db->admin();

        self::assertSame(
            Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_UNBOUND_USERS,
            $this->singleViolation($this->validate([$this->update($id, ['login_type' => 'both'])]))->getCode(),
        );

        $this->confirmations->confirm($id, $this->actingAdmin);
        $this->assertNoViolations($this->validate([$this->update($id, ['login_type' => 'both'])]));
        self::assertEquals([new PasswordSessionRevocationMessage('admin')], $this->written($id));
    }

    public function testDeactivatingTheLastAdminProviderUnderSsoOnlyModeIsRejected(): void
    {
        $flagged = $this->db->provider(['disable_non_oidc_admin_login' => 1]);
        $this->db->bind($flagged, $this->db->admin());
        $other = $this->db->provider(['disable_non_oidc_admin_login' => 1]);

        self::assertSame(
            Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD,
            $this->singleViolation($this->validate([$this->update($flagged, ['is_active' => 0])]))->getCode(),
        );
        self::assertSame(
            Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD,
            $this->singleViolation($this->validate([$this->delete($flagged)], bindingLossConfirmed: true))->getCode(),
        );

        // Without another flagged provider, password login simply comes back.
        $this->db->connection->executeStatement('DELETE FROM `sw6oidc_provider` WHERE `id` = :id', ['id' => Uuid::fromHexToBytes($other)], ['id' => \Doctrine\DBAL\ParameterType::BINARY]);
        $this->assertNoViolations($this->validate([$this->delete($flagged)], bindingLossConfirmed: true));
    }

    /**
     * R3-M15: requiring a verified email while the email is transformed
     * would refuse every login.
     */
    public function testVerifiedEmailCanOnlyBeRequiredForAnUntransformedEmailClaim(): void
    {
        $id = $this->db->provider(['require_email_verified' => 0]);
        $this->db->attributeMapping($id, ['attribute_type' => 'email', 'attribute_name' => 'email', 'transform_function' => 'regex_replace', 'transform_params' => '{"pattern":"/x/"}']);

        $violation = $this->singleViolation($this->validate([$this->update($id, ['require_email_verified' => 1])]));
        self::assertSame('/requireEmailVerified', $violation->getPropertyPath());

        $this->db->connection->executeStatement('UPDATE `sw6oidc_attribute_mapping` SET `transform_function` = NULL');
        $this->assertNoViolations($this->validate([$this->update($id, ['require_email_verified' => 1])]));
    }

    /**
     * R3-M9: bindings belong to an issuer; changing it needs a decision.
     */
    public function testIssuerChangeWithBoundAccountsNeedsADecision(): void
    {
        $id = $this->db->provider(['issuer' => 'https://idp.example']);
        $this->db->bind($id, Uuid::randomHex(), 'customer');

        $violation = $this->singleViolation($this->validate([$this->update($id, ['issuer' => 'https://other-tenant.example'])]));
        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_ISSUER_CHANGE_CONFIRM, $violation->getCode());
        self::assertStringContainsString('1 account', (string) $violation->getMessage());

        // Unchanged issuer, or no bound accounts: nothing to decide.
        $this->assertNoViolations($this->validate([$this->update($id, ['issuer' => 'https://idp.example'])]));
        $this->assertNoViolations($this->validate([$this->update($this->db->provider(['issuer' => 'https://a.example']), ['issuer' => 'https://b.example'])]));
    }

    public function testRebindingMovesTheBindingsToTheNewIssuerAfterCommit(): void
    {
        $id = $this->db->provider(['issuer' => 'https://idp.example']);
        $this->db->bind($id, Uuid::randomHex(), 'customer');
        $this->issuerChanges->confirm($id, $this->actingAdmin, true);

        $this->assertNoViolations($this->validate([$this->update($id, ['issuer' => 'https://idp.example/realms/shop'])]));
        $this->written($id);

        self::assertSame(
            [hash('sha256', 'https://idp.example/realms/shop')],
            $this->db->connection->fetchFirstColumn('SELECT `issuer_hash` FROM `sw6oidc_user_provider`'),
        );
    }

    public function testDisconnectingTheOnlyAdminBindingsUnderSsoOnlyModeIsRefused(): void
    {
        $id = $this->db->provider(['issuer' => 'https://idp.example', 'disable_non_oidc_admin_login' => 1]);
        $this->db->bind($id, $this->db->admin());
        $this->issuerChanges->confirm($id, $this->actingAdmin, false);

        $violation = $this->singleViolation($this->validate([$this->update($id, ['issuer' => 'https://other-tenant.example'])]));

        self::assertSame(Sw6OidcProviderWriteGuardSubscriber::CODE_LOCKOUT_GUARD, $violation->getCode());
    }

    public function testBreakGlassSkipsTheLockoutChecks(): void
    {
        $this->assertNoViolations($this->validate([$this->update($this->db->provider(), ['disable_non_oidc_admin_login' => 1])], breakGlass: true));
    }

    public function testCliCountsAsConfirmed(): void
    {
        $id = $this->db->provider();
        $this->db->bind($id, $this->db->admin());
        $this->db->admin();

        $this->assertNoViolations($this->validate([$this->update($id, ['disable_non_oidc_admin_login' => 1])], withRequest: false));
    }

    public function testFailedWriteLeavesNoRevocationBehind(): void
    {
        $id = $this->db->provider();
        $this->db->bind($id, Uuid::randomHex(), 'customer');
        $this->validate([$this->update($id, ['disable_non_oidc_customer_login' => 1])]);

        // The write failed; the next validation starts clean.
        $this->subscriber->validate(new PreWriteValidationEvent(WriteContext::createFromContext(Context::createDefaultContext()), [$this->update($id, ['scope' => 'openid'])]));

        self::assertSame([], $this->written($id));
    }

    /**
     * @param list<WriteCommand> $commands
     */
    private function validate(array $commands, bool $privateIps = false, bool $breakGlass = false, bool $withRequest = true, bool $bindingLossConfirmed = false): PreWriteValidationEvent
    {
        $requestStack = new RequestStack();

        if ($withRequest) {
            $requestStack->push(new Request());
        }

        $bus = new class($this->dispatched) implements MessageBusInterface {
            /**
             * @param list<object> $dispatched
             */
            public function __construct(public array &$dispatched)
            {
            }

            public function dispatch(object $message, array $stamps = []): Envelope
            {
                $this->dispatched[] = $message;

                return new Envelope($message);
            }
        };

        $this->subscriber = new Sw6OidcProviderWriteGuardSubscriber(
            new SsrfUrlValidator(false, static fn (): array => [$privateIps ? '10.0.0.1' : '93.184.215.14']),
            $this->db->connection,
            new Sw6OidcEncryptor(self::APP_SECRET),
            new SsoOnlyInvariant($this->db->connection, $breakGlass),
            $bus,
            $requestStack,
            $this->confirmations,
            new NullLogger(),
            $this->issuerChanges,
        );

        $source = new AdminApiSource($this->actingAdmin);
        $source->setIsAdmin(true);
        $context = new Context($source);

        if ($bindingLossConfirmed) {
            $context->addState(Sw6OidcProviderWriteGuardSubscriber::STATE_BINDING_LOSS_CONFIRMED);
        }

        $event = new PreWriteValidationEvent(WriteContext::createFromContext($context), $commands);
        $this->subscriber->validate($event);

        return $event;
    }

    /**
     * @return list<object> the messages dispatched once the provider write is committed
     */
    private function written(string $id): array
    {
        $this->dispatched = [];
        $this->subscriber->onProviderWritten(new EntityWrittenEvent(
            Sw6OidcProviderDefinition::ENTITY_NAME,
            [new EntityWriteResult($id, [], Sw6OidcProviderDefinition::ENTITY_NAME, EntityWriteResult::OPERATION_UPDATE)],
            Context::createDefaultContext(),
        ));

        return $this->dispatched;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function update(string $id, array $payload): WriteCommand
    {
        return $this->command(UpdateCommand::class, $id, $payload);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function insert(array $payload): WriteCommand
    {
        return $this->command(InsertCommand::class, Uuid::randomHex(), $payload);
    }

    private function delete(string $id): WriteCommand
    {
        return $this->command(DeleteCommand::class, $id, []);
    }

    /**
     * @param class-string<WriteCommand> $class
     * @param array<string, mixed>       $payload
     */
    private function command(string $class, string $id, array $payload): WriteCommand
    {
        $command = $this->createStub($class);
        $command->method('getEntityName')->willReturn(Sw6OidcProviderDefinition::ENTITY_NAME);
        $command->method('getPayload')->willReturn($payload);
        $command->method('getPrimaryKey')->willReturn(['id' => Uuid::fromHexToBytes($id)]);
        $command->method('getPath')->willReturn('/0');

        return $command;
    }

    private function assertNoViolations(PreWriteValidationEvent $event): void
    {
        $messages = [];

        foreach ($event->getExceptions()->getExceptions() as $exception) {
            if ($exception instanceof WriteConstraintViolationException) {
                foreach ($exception->getViolations() as $violation) {
                    $messages[] = $violation->getCode() . ': ' . $violation->getMessage();
                }
            }
        }

        self::assertSame([], $messages);
    }

    private function singleViolation(PreWriteValidationEvent $event): ConstraintViolationInterface
    {
        $exceptions = $event->getExceptions()->getExceptions();
        self::assertCount(1, $exceptions);
        $exception = array_values($exceptions)[0];
        self::assertInstanceOf(WriteConstraintViolationException::class, $exception);
        self::assertCount(1, $exception->getViolations());

        return $exception->getViolations()->get(0);
    }
}
