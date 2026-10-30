<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Provisioning;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\ProviderMismatchException;
use MartinKuhl\Sw6Oidc\Service\Provisioning\Exception\SubjectAlreadyLinkedException;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Context;

/**
 * Creates an account for an IdP identity and binds it, in one transaction:
 * a concurrent first login of the same subject must not leave an unbound
 * duplicate behind (R3-M12). If the other login won the race, its account
 * is used. One implementation for customers and admins (R8-L10).
 */
class JitAccountCreator
{
    public function __construct(
        private readonly Connection $connection,
        private readonly UserProviderBindingService $bindingService,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @param \Closure(): string $create   creates the account, returns its id
     * @param string|null        $bindingScope the sales channel of a channel-bound customer
     * @param string|null        $lookupScope  the sales channel to look the winner up in
     *
     * @return array{id: string, created: bool}
     */
    public function createAndBind(
        string $userType,
        ExternalIdentity $identity,
        Context $context,
        \Closure $create,
        ?string $bindingScope = null,
        ?string $lookupScope = null,
    ): array {
        try {
            $id = $this->connection->transactional(function () use ($create, $userType, $identity, $context, $bindingScope): string {
                $id = $create();
                $this->bindingService->bind($userType, $id, $identity, $context, $bindingScope);

                return $id;
            });

            return ['id' => $id, 'created' => true];
        } catch (UniqueConstraintViolationException | SubjectAlreadyLinkedException | ProviderMismatchException $exception) {
            $winnerId = $this->bindingService->findUserIdBySubject($userType, $identity, $context, $lookupScope);

            if ($winnerId === null) {
                throw $exception;
            }

            $this->logger->info('sw6oidc: concurrent first login; using the account the other login created.', [
                'providerId' => $identity->providerId,
                'userType' => $userType,
                'userId' => $winnerId,
            ]);

            return ['id' => $winnerId, 'created' => false];
        }
    }
}
