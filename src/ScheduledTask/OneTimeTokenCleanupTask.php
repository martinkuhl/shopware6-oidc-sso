<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\ScheduledTask;

use Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTask;

/**
 * Hourly pruning of expired one-time tokens (`sw6oidc_one_time_token`):
 * every anonymous flow start and passkey ceremony writes a row, so a daily
 * prune can't keep up with crawlers and busy shops (R3-M17).
 */
class OneTimeTokenCleanupTask extends ScheduledTask
{
    public static function getTaskName(): string
    {
        return 'sw6oidc.one_time_token_cleanup';
    }

    public static function getDefaultInterval(): int
    {
        return self::HOURLY;
    }

    public static function shouldRescheduleOnFailure(): bool
    {
        return true;
    }
}
