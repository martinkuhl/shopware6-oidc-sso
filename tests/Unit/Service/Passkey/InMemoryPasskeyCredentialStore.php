<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Passkey;

use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialCollection;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialDefinition;
use MartinKuhl\Sw6Oidc\Core\Content\PasskeyCredential\Sw6OidcPasskeyCredentialEntity;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\MockObject\MockObject;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenContainerEvent;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Backs a mocked sw6oidc_passkey_credential.repository with a plain array,
 * supporting just the EqualsFilter lookups PasskeyCredentialRepository uses.
 */
final class InMemoryPasskeyCredentialStore
{
    /** @var array<string, array<string, mixed>> */
    public array $rows = [];

    /**
     * @param array<string, mixed> $row camelCase field => value
     */
    public function add(array $row): void
    {
        // Rows written before the hash column existed get it like the migration backfills it.
        $this->rows[(string) $row['id']] = $row + [
            'signCount' => 0,
            'nickname' => null,
            'credentialIdHash' => hash('sha256', (string) $row['credentialId']),
        ];
    }

    /**
     * The repository's conditional counter UPDATE, applied to the rows.
     */
    public function connection(Connection&MockObject $mock): Connection
    {
        $mock->method('executeStatement')->willReturnCallback(function (string $sql, array $params): int {
            \assert(str_contains($sql, 'UPDATE `sw6oidc_passkey_credential`'));
            $id = Uuid::fromBytesToHex($params['id']);
            $row = $this->rows[$id] ?? null;

            if ($row === null || !($row['signCount'] < $params['counter'] || $params['counter'] === 0)) {
                return 0;
            }

            $this->rows[$id] = ['publicKey' => $params['publicKey'], 'signCount' => $params['counter']] + $row;

            return 1;
        });

        return $mock;
    }

    public function wire(EntityRepository&MockObject $mock): EntityRepository
    {
        $mock->method('search')->willReturnCallback(fn (Criteria $criteria, Context $context): EntitySearchResult => $this->search($criteria, $context));
        $mock->method('create')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            foreach ($payload as $row) {
                $this->add($row);
            }

            return EntityWrittenContainerEvent::createWithWrittenEvents([], $context, []);
        });
        $mock->method('update')->willReturnCallback(function (array $payload, Context $context): EntityWrittenContainerEvent {
            foreach ($payload as $row) {
                $this->rows[(string) $row['id']] = array_merge($this->rows[(string) $row['id']], $row);
            }

            return EntityWrittenContainerEvent::createWithWrittenEvents([], $context, []);
        });

        return $mock;
    }

    private function search(Criteria $criteria, Context $context): EntitySearchResult
    {
        $matches = array_filter($this->rows, static function (array $row) use ($criteria): bool {
            foreach ($criteria->getFilters() as $filter) {
                if ($filter instanceof EqualsFilter && ($row[$filter->getField()] ?? null) !== $filter->getValue()) {
                    return false;
                }
            }

            return true;
        });

        $entities = array_map(static function (array $row): Sw6OidcPasskeyCredentialEntity {
            $entity = new Sw6OidcPasskeyCredentialEntity();
            $entity->assign($row);

            return $entity;
        }, array_values($matches));

        return new EntitySearchResult(
            Sw6OidcPasskeyCredentialDefinition::ENTITY_NAME,
            \count($entities),
            new Sw6OidcPasskeyCredentialCollection($entities),
            null,
            $criteria,
            $context,
        );
    }
}
