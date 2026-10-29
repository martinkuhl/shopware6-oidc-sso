<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\ExternalIdentity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\IdentityResolver;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;

#[CoversClass(IdentityResolver::class)]
final class IdentityResolverTest extends TestCase
{
    private const TYPE = Sw6OidcUserProviderEntity::USER_TYPE_ADMIN;

    private UserProviderBindingService&MockObject $bindings;

    private Sw6OidcProviderEntity $provider;

    private Context $context;

    private ?string $subjectOwner = null;

    private ?Sw6OidcUserProviderEntity $accountBinding = null;

    protected function setUp(): void
    {
        $this->context = Context::createDefaultContext();
        $this->provider = new Sw6OidcProviderEntity();
        $this->provider->setId(Uuid::randomHex());

        $this->bindings = $this->createMock(UserProviderBindingService::class);
        $this->bindings->method('findUserIdBySubject')->willReturnCallback(fn (): ?string => $this->subjectOwner);
        $this->bindings->method('getBinding')->willReturnCallback(fn (): ?Sw6OidcUserProviderEntity => $this->accountBinding);
    }

    public function testBoundSubjectWinsOverEmail(): void
    {
        $this->subjectOwner = 'bound-user';
        $this->bindings->expects(self::never())->method('bind');

        self::assertSame('bound-user', $this->resolve('email-user'));
    }

    public function testNoAccountAtAllMeansCreate(): void
    {
        self::assertNull($this->resolve(null));
    }

    public function testUnverifiedEmailIsRefusedWhenRequired(): void
    {
        $this->subjectOwner = 'bound-user';

        $this->expectException(EmailNotVerifiedException::class);

        $this->resolve('bound-user', verified: false);
    }

    public function testUnverifiedEmailIsAcceptedForBoundSubjectsWhenNotRequired(): void
    {
        $this->provider->setRequireEmailVerified(false);
        $this->subjectOwner = 'bound-user';

        self::assertSame('bound-user', $this->resolve(null, verified: false));
    }

    public function testUnboundEmailMatchIsNotLinkedByDefault(): void
    {
        $this->bindings->expects(self::never())->method('bind');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->resolve('email-user');
    }

    public function testUnboundEmailMatchIsLinkedWhenAllowedAndVerified(): void
    {
        $this->provider->setLinkExistingAccounts(true);
        $this->bindings->expects(self::once())->method('bind')->with(self::TYPE, 'email-user');

        self::assertSame('email-user', $this->resolve('email-user'));
    }

    public function testUnverifiedEmailIsNeverLinkedEvenWhenVerificationIsOptional(): void
    {
        $this->provider->setRequireEmailVerified(false);
        $this->provider->setLinkExistingAccounts(true);
        $this->bindings->expects(self::never())->method('bind');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->resolve('email-user', verified: false);
    }

    public function testPrivilegedAccountIsNeverLinkedByEmail(): void
    {
        $this->provider->setLinkExistingAccounts(true);
        $this->bindings->expects(self::never())->method('bind');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->resolve('email-user', privileged: true);
    }

    public function testAccountBoundToAnotherProviderIsRefused(): void
    {
        $this->accountBinding = $this->binding(Uuid::randomHex(), null);

        $this->expectException(ProviderMismatchException::class);

        $this->resolve('email-user');
    }

    public function testAccountBoundToAnotherSubjectOfTheSameProviderIsRefused(): void
    {
        $this->accountBinding = $this->binding($this->provider->getId(), 'someone-else');
        $this->bindings->expects(self::never())->method('backfillSubject');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->resolve('email-user');
    }

    public function testLegacyBindingIsBackfilled(): void
    {
        $this->accountBinding = $this->binding($this->provider->getId(), null);
        $this->bindings->expects(self::once())->method('backfillSubject');

        self::assertSame('email-user', $this->resolve('email-user'));
    }

    /**
     * R3-M10: whoever holds a (possibly recycled) email at the IdP today
     * must not inherit a privileged account through its legacy binding.
     */
    public function testLegacyBindingOfAPrivilegedAccountIsNotUpgraded(): void
    {
        $this->accountBinding = $this->binding($this->provider->getId(), null);
        $this->bindings->expects(self::never())->method('backfillSubject');

        $this->expectException(AccountLinkingRequiredException::class);

        $this->resolve('email-user', privileged: true);
    }

    /**
     * R3-M9: a binding to this provider under another issuer (the provider
     * now points at another tenant) never hands the account over.
     */
    public function testBindingUnderAnotherIssuerIsNotTakenOver(): void
    {
        $this->accountBinding = $this->binding($this->provider->getId(), 'subject-1');
        $this->bindings->expects(self::never())->method('bind');

        $this->expectException(AccountLinkingRequiredException::class);

        // The subject lookup (issuer-scoped) found nothing; the email matches the bound account.
        $this->resolve('email-user');
    }

    public function testExplicitLinkBindsEvenASuperadmin(): void
    {
        $this->bindings->expects(self::once())->method('bind')->with(self::TYPE, 'me');

        (new IdentityResolver($this->bindings, new NullLogger()))->linkExplicitly(self::TYPE, 'me', $this->identity(true), $this->context);
    }

    public function testExplicitLinkRefusesASubjectOwnedByAnotherAccount(): void
    {
        $this->subjectOwner = 'someone-else';

        $this->expectException(SubjectAlreadyLinkedException::class);

        (new IdentityResolver($this->bindings, new NullLogger()))->linkExplicitly(self::TYPE, 'me', $this->identity(true), $this->context);
    }

    public function testExplicitLinkRefusesAnAccountBoundElsewhere(): void
    {
        $this->accountBinding = $this->binding(Uuid::randomHex(), 'x');

        $this->expectException(ProviderMismatchException::class);

        (new IdentityResolver($this->bindings, new NullLogger()))->linkExplicitly(self::TYPE, 'me', $this->identity(true), $this->context);
    }

    private function resolve(?string $emailMatch, bool $verified = true, bool $privileged = false): ?string
    {
        return (new IdentityResolver($this->bindings, new NullLogger()))->resolve(
            self::TYPE,
            $this->provider,
            $this->identity($verified),
            $emailMatch,
            $privileged,
            $this->context,
        );
    }

    private function identity(bool $verified): ExternalIdentity
    {
        return new ExternalIdentity($this->provider->getId(), 'https://idp.example.com', 'subject-1', 'jane@example.com', $verified);
    }

    private function binding(string $providerId, ?string $sub): Sw6OidcUserProviderEntity
    {
        $binding = new Sw6OidcUserProviderEntity();
        $binding->setId(Uuid::randomHex());
        $binding->setUserType(self::TYPE);
        $binding->setUserId('email-user');
        $binding->setProviderId($providerId);
        $binding->setSub($sub);

        return $binding;
    }
}
