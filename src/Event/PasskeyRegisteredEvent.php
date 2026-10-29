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
 * A new passkey was registered on an account. A passkey is a permanent way
 * in, so this is a security event: it is written to the audit log
 * (log_entry, via LogAware) and is available as a Flow Builder trigger
 * ("sw6oidc.passkey.registered") with the account owner as mail recipient —
 * shops can send a "a new passkey was added to your account" notice.
 */
class PasskeyRegisteredEvent extends Event implements FlowEventAware, MailAware, ScalarValuesAware, LogAware
{
    public const EVENT_NAME = 'sw6oidc.passkey.registered';

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

    public function getName(): string
    {
        return self::EVENT_NAME;
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
        return ['userType' => $this->userType, 'userId' => $this->userId, 'nickname' => $this->nickname];
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
