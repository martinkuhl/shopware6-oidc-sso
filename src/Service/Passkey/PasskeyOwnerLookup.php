<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Event\AbstractPasskeyAccountEvent;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Uuid\Uuid;

/**
 * Builds the passkey account events from ids alone (deletion and clone
 * detection know only the credential's owner ids): the owner's email and
 * name for the mail recipient, and a customer's sales channel.
 */
class PasskeyOwnerLookup
{
    public function __construct(private readonly Connection $connection)
    {
    }

    /**
     * @template T of AbstractPasskeyAccountEvent
     *
     * @param class-string<T> $eventClass
     *
     * @return T|null null when the owner no longer exists
     */
    public function event(string $eventClass, string $userType, string $userId, ?string $nickname, Context $context): ?AbstractPasskeyAccountEvent
    {
        $table = $userType === LoginType::Admin->value ? 'user' : 'customer';
        $channel = $table === 'customer' ? ', LOWER(HEX(`sales_channel_id`)) AS `salesChannelId`' : ', NULL AS `salesChannelId`';

        $row = $this->connection->fetchAssociative(
            sprintf('SELECT `email`, `first_name` AS `firstName`, `last_name` AS `lastName`%s FROM `%s` WHERE `id` = :id', $channel, $table),
            ['id' => Uuid::fromHexToBytes($userId)],
        );

        if ($row === false || !\is_string($row['email'] ?? null) || $row['email'] === '') {
            return null;
        }

        return new $eventClass(
            $userType,
            $userId,
            $row['email'],
            trim($row['firstName'] . ' ' . $row['lastName']),
            $nickname,
            \is_string($row['salesChannelId'] ?? null) ? $row['salesChannelId'] : null,
            $context,
        );
    }
}
