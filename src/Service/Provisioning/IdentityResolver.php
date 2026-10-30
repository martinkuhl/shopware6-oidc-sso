<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\AccountLinkingRequiredException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\EmailNotVerifiedException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * Decides which Shopware account an IdP identity logs into — shared by
 * customer and admin provisioning so both follow the same rules:
 *
 * 1. the account bound to this provider + issuer + subject (in the sales
 *    channel's scope first, then globally);
 * 2. an unbound email-matched account, linked only if the provider allows
 *    linking, the email is verified and the account isn't privileged
 *    (superadmins are only ever linked explicitly, see linkExplicitly());
 * 3. no account at all: null, the caller may create one.
 *
 * Anything else throws. The email claim alone is never proof of ownership
 * of an existing account.
 */
class IdentityResolver
{
    public function __construct(
        private readonly UserProviderBindingService $bindingService,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param string|null $emailMatchedUserId     the account whose email equals the claim, if any
     * @param bool        $emailMatchIsPrivileged whether that account is privileged (every admin)
     * @param string|null $salesChannelId         the Storefront login's sales channel (binding lookup scope)
     * @param string|null $emailMatchScope        the binding scope for linking the email-matched account
     *
     * @throws EmailNotVerifiedException
     * @throws ProviderMismatchException
     * @throws AccountLinkingRequiredException
     *
     * @return string|null the account id, or null when no account exists yet
     */
    public function resolve(
        string $userType,
        Sw6OidcProviderEntity $provider,
        ExternalIdentity $identity,
        ?string $emailMatchedUserId,
        bool $emailMatchIsPrivileged,
        Context $context,
        ?string $salesChannelId = null,
        ?string $emailMatchScope = null,
    ): ?string {
        if ($provider->isRequireEmailVerified() && !$identity->emailVerified) {
            throw new EmailNotVerifiedException('The identity provider did not verify this email address.');
        }

        $boundUserId = $this->bindingService->findUserIdBySubject($userType, $identity, $context, $salesChannelId);

        if ($boundUserId !== null) {
            return $boundUserId;
        }

        if ($emailMatchedUserId === null) {
            return null;
        }

        $binding = $this->bindingService->getBinding($userType, $emailMatchedUserId, $context);

        if ($binding instanceof Sw6OidcUserProviderEntity) {
            if ($binding->getProviderId() !== $identity->providerId) {
                throw new ProviderMismatchException(sprintf('This %s account is bound to a different identity provider.', $userType));
            }

            // Same provider, different subject or issuer: the email moved to
            // another IdP account, or the provider now points at another
            // tenant. Never hand the account over.
            $this->logger->warning('sw6oidc: login refused, the email-matched account is bound to another identity of this provider.', [
                'providerId' => $identity->providerId,
                'userType' => $userType,
                'userId' => $emailMatchedUserId,
            ]);

            throw new AccountLinkingRequiredException('This account is linked to a different identity at this provider.');
        }

        if (!$provider->isLinkExistingAccounts() || !$identity->emailVerified || $emailMatchIsPrivileged) {
            throw new AccountLinkingRequiredException('An account with this email exists and must be connected explicitly.');
        }

        $this->bindingService->bind($userType, $emailMatchedUserId, $identity, $context, $emailMatchScope);

        $this->logger->info('sw6oidc: existing account linked to provider by verified email.', [
            'providerId' => $identity->providerId,
            'userType' => $userType,
            'userId' => $emailMatchedUserId,
        ]);

        return $emailMatchedUserId;
    }

    /**
     * "Connect SSO" from a logged-in account: the owner proved control of the
     * account (session + step-up) and of the IdP identity (this login), so no
     * email match is needed. The only way to bind a superadmin.
     *
     * @throws ProviderMismatchException     when the account is bound to another provider or subject
     * @throws SubjectAlreadyLinkedException when the subject is bound to another account
     */
    public function linkExplicitly(string $userType, string $userId, ExternalIdentity $identity, Context $context, ?string $bindingScope = null): void
    {
        $subjectOwner = $this->bindingService->findUserIdBySubject($userType, $identity, $context, $bindingScope);

        if ($subjectOwner !== null && $subjectOwner !== $userId) {
            throw new SubjectAlreadyLinkedException(sprintf('This identity is already linked to another %s account.', $userType));
        }

        $binding = $this->bindingService->getBinding($userType, $userId, $context);

        if ($binding instanceof Sw6OidcUserProviderEntity) {
            if (
                $binding->getProviderId() !== $identity->providerId
                || $binding->getSub() !== $identity->subject
                || $binding->getIssuerHash() !== UserProviderBindingService::issuerHash($identity->issuer)
            ) {
                throw new ProviderMismatchException(sprintf('This %s account is already bound to a different identity.', $userType));
            }

            return;
        }

        $this->bindingService->bind($userType, $userId, $identity, $context, $bindingScope);

        $this->logger->info('sw6oidc: account explicitly connected to provider.', [
            'providerId' => $identity->providerId,
            'userType' => $userType,
            'userId' => $userId,
        ]);
    }
}
