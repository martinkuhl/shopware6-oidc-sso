<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Event;

use Monolog\Level;
use Shopware\Core\Content\Flow\Dispatching\Aware\ScalarValuesAware;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Event\EventData\EventDataCollection;
use Shopware\Core\Framework\Event\EventData\MailRecipientStruct;
use Shopware\Core\Framework\Event\EventData\ScalarValueType;
use Shopware\Core\Framework\Event\FlowEventAware;
use Shopware\Core\Framework\Event\MailAware;
use Shopware\Core\Framework\Log\LogAware;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Something security-relevant happened to one of an account's passkeys: a
 * Flow Builder trigger with the owner as mail recipient, and an audit log
 * entry (LogAware).
 */
abstract class AbstractPasskeyAccountEvent extends Event implements FlowEventAware, MailAware, ScalarValuesAware, LogAware
{
    public function __construct(
        private readonly string $userType,
        private readonly string $userId,
        private readonly string $email,
        private readonly string $displayName,
        private readonly ?string $nickname,
        private readonly ?string $salesChannelId,
        private readonly Context $context,
    ) {
    }

    public static function getAvailableData(): EventDataCollection
    {
        return (new EventDataCollection())
            ->add('userType', new ScalarValueType(ScalarValueType::TYPE_STRING))
            ->add('userId', new ScalarValueType(ScalarValueType::TYPE_STRING))
            ->add('nickname', new ScalarValueType(ScalarValueType::TYPE_STRING));
    }

    public function getContext(): Context
    {
        return $this->context;
    }

    public function getMailStruct(): MailRecipientStruct
    {
        return new MailRecipientStruct([$this->email => $this->displayName !== '' ? $this->displayName : $this->email]);
    }

    public function getSalesChannelId(): ?string
    {
        return $this->salesChannelId;
    }

    /**
     * @return array<string, scalar|null>
     */
    public function getValues(): array
    {
        return ['userType' => $this->userType, 'userId' => $this->userId, 'nickname' => $this->nickname];
    }

    /**
     * @return array<string, mixed>
     */
    public function getLogData(): array
    {
        return $this->getValues();
    }

    public function getLogLevel(): Level
    {
        return Level::Notice;
    }

    public function getUserType(): string
    {
        return $this->userType;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }
}
