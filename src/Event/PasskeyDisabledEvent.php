<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Event;

use Monolog\Level;

/**
 * A passkey was disabled because its signature counter went backwards — a
 * possibly cloned authenticator: Flow Builder trigger
 * "sw6oidc.passkey.disabled", e.g. to alert the owner or the shop.
 */
class PasskeyDisabledEvent extends AbstractPasskeyAccountEvent
{
    public const EVENT_NAME = 'sw6oidc.passkey.disabled';

    public function getName(): string
    {
        return self::EVENT_NAME;
    }

    public function getLogLevel(): Level
    {
        return Level::Warning;
    }
}
