<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsAnyFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Reads and writes sw6oidc_user_provider: which IdP identity owns which
 * Shopware user/customer. The identity is provider + issuer + subject,
 * compared byte-exactly (R3-M9) — repointing a provider at another tenant
 * never logs its subjects into the old tenant's accounts. An account has at
 * most one binding.
 *
 * Customers bound to a sales channel (Shopware's "bind customers to sales
 * channel") are bound in that channel's scope, so one IdP subject can own
 * one customer account per sales channel; everyone else is bound globally
 * (R3-M14). A login looks for the binding in its sales channel's scope
 * first, then for the global one.
 */
class UserProviderBindingService
{
    /**
     * @param EntityRepository<Sw6OidcUserProviderCollection> $userProviderRepository
     */
    public function __construct(private readonly EntityRepository $userProviderRepository)
    {
    }

    public static function issuerHash(string $issuer): string
    {
        return hash('sha256', $issuer);
    }

    public function getBinding(string $userType, string $userId, Context $context): ?Sw6OidcUserProviderEntity
    {
        $entity = $this->userProviderRepository
            ->search($this->userCriteria($userType, $userId), $context)
            ->first();

        \assert($entity === null || $entity instanceof Sw6OidcUserProviderEntity);

        return $entity;
    }

    public function getBoundProviderId(string $userType, string $userId, Context $context): ?string
    {
        return $this->getBinding($userType, $userId, $context)?->getProviderId();
    }

    /**
     * The binding this IdP identity logs in with: the one in the sales
     * channel's scope, else the global one.
     */
    public function findBindingBySubject(string $userType, ExternalIdentity $identity, Context $context, ?string $salesChannelId = null): ?Sw6OidcUserProviderEntity
    {
        $scopes = array_values(array_unique(array_filter([$salesChannelId, Sw6OidcUserProviderEntity::GLOBAL_SCOPE])));
        $bindings = $this->userProviderRepository->search($this->subjectCriteria($userType, $identity, $scopes), $context)->getEntities();

        $global = null;

        foreach ($bindings as $binding) {
            if ($binding->getBindingScope() !== Sw6OidcUserProviderEntity::GLOBAL_SCOPE) {
                return $binding;
            }

            $global = $binding;
        }

        return $global;
    }

    /**
     * The account this IdP identity is bound to, if any (see findBindingBySubject()).
     */
    public function findUserIdBySubject(string $userType, ExternalIdentity $identity, Context $context, ?string $salesChannelId = null): ?string
    {
        return $this->findBindingBySubject($userType, $identity, $context, $salesChannelId)?->getUserId();
    }


    /**
     * Binds an unbound account to an IdP identity. A concurrent first login
     * for the same account or subject loses the unique-key race; it then
     * re-reads and accepts the binding only if it is the identical one.
     *
     * @param string|null $bindingScope the channel-bound customer's sales channel; null = global
     *
     * @throws ProviderMismatchException     when the account got bound to another provider/subject
     * @throws SubjectAlreadyLinkedException when the subject is already bound to another account
     */
    public function bind(string $userType, string $userId, ExternalIdentity $identity, Context $context, ?string $bindingScope = null): void
    {
        $scope = $bindingScope ?? Sw6OidcUserProviderEntity::GLOBAL_SCOPE;
        $existing = $this->userProviderRepository->search($this->subjectCriteria($userType, $identity, [$scope]), $context)->first();
        $existingUserId = $existing instanceof Sw6OidcUserProviderEntity ? $existing->getUserId() : null;

        if ($existingUserId !== null && $existingUserId !== $userId) {
            throw new SubjectAlreadyLinkedException(sprintf('This identity is already linked to another %s account.', $userType));
        }

        if ($existingUserId === $userId) {
            return;
        }

        try {
            $this->asSystem($context, fn (Context $systemContext): EntityWrittenContainerEvent => $this->userProviderRepository->create([[
                'id' => Uuid::randomHex(),
                'userType' => $userType,
                'userId' => $userId,
                'providerId' => $identity->providerId,
                'issuer' => $identity->issuer,
                'issuerHash' => self::issuerHash($identity->issuer),
                'sub' => $identity->subject,
                'bindingScope' => $scope,
            ]], $systemContext));
        } catch (UniqueConstraintViolationException $exception) {
            $binding = $this->getBinding($userType, $userId, $context);

            if (
                !$binding instanceof Sw6OidcUserProviderEntity
                || $binding->getProviderId() !== $identity->providerId
                || $binding->getSub() !== $identity->subject
                || $binding->getIssuerHash() !== self::issuerHash($identity->issuer)
            ) {
                throw new ProviderMismatchException(sprintf('This %s account is bound to a different identity.', $userType), $exception);
            }
        }
    }

    /**
     * Upgrades a legacy (pre-subject) binding to the identity that just
     * authenticated through its provider.
     */
    public function backfillSubject(Sw6OidcUserProviderEntity $binding, ExternalIdentity $identity, Context $context): void
    {
        $this->asSystem($context, fn (Context $systemContext): EntityWrittenContainerEvent => $this->userProviderRepository->update([[
            'id' => $binding->getId(),
            'issuer' => $identity->issuer,
            'issuerHash' => self::issuerHash($identity->issuer),
            'sub' => $identity->subject,
        ]], $systemContext));
    }

    public function unbind(string $userType, string $userId, Context $context): void
    {
        $ids = $this->userProviderRepository
            ->searchIds($this->userCriteria($userType, $userId), $context)
            ->getIds();

        if ($ids === []) {
            return;
        }

        $this->asSystem($context, fn (Context $systemContext): EntityWrittenContainerEvent => $this->userProviderRepository->delete(
            array_map(static fn (string $id): array => ['id' => $id], $ids),
            $systemContext,
        ));
    }

    /**
     * Bindings are writable in system scope only (R3-H3); this service is
     * their one writer, whatever context its caller holds.
     *
     * @param \Closure(Context): mixed $write
     */
    private function asSystem(Context $context, \Closure $write): void
    {
        $context->scope(Context::SYSTEM_SCOPE, $write);
    }

    /**
     * @param list<string> $scopes
     */
    private function subjectCriteria(string $userType, ExternalIdentity $identity, array $scopes): Criteria
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->addFilter(new EqualsFilter('providerId', $identity->providerId));
        $criteria->addFilter(new EqualsFilter('issuerHash', self::issuerHash($identity->issuer)));
        $criteria->addFilter(new EqualsFilter('sub', $identity->subject));
        $criteria->addFilter(new EqualsAnyFilter('bindingScope', $scopes));

        return $criteria;
    }

    private function userCriteria(string $userType, string $userId): Criteria
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->addFilter(new EqualsFilter('userId', $userId));

        return $criteria;
    }
}
