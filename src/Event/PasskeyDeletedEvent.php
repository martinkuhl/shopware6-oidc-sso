<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Event;

/**
 * A passkey was removed from an account (by its owner, an admin or account
 * cleanup): Flow Builder trigger "sw6oidc.passkey.deleted", e.g. for a
 * "a passkey was removed from your account" notice.
 */
class PasskeyDeletedEvent extends AbstractPasskeyAccountEvent
{
    public const EVENT_NAME = 'sw6oidc.passkey.deleted';

    public function getName(): string
    {
        return self::EVENT_NAME;
    }
}
