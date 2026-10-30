<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Health;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;

/**
 * The cron-owned health-alert state of one provider, and the transition
 * rules. Alerts fire **once per outage**: an outage starts with the first
 * failed probe (`firstFailureAt`) and is alerted when the consecutive failure
 * count reaches the threshold and nothing was sent since it started. Editing
 * the provider mid-outage (e.g. lowering the threshold) never re-fires —
 * admin writes can't touch this state (WriteProtected fields).
 */
final readonly class HealthAlertState
{
    public const STATUS_OK = 'ok';
    public const STATUS_FAIL = 'fail';

    /**
     * Healthy again, but the recovery notice hasn't been delivered yet: kept
     * until the webhook accepts it, so a failed delivery is retried on the
     * next run (R8-L17). The provider counts as reachable.
     */
    public const STATUS_RECOVERY_PENDING = 'recovery_pending';

    public const NOTIFY_UNHEALTHY = 'unhealthy';
    public const NOTIFY_RECOVERED = 'recovered';

    public function __construct(
        public int $consecutiveFailures = 0,
        public ?string $lastStatus = null,
        public ?\DateTimeImmutable $firstFailureAt = null,
        public ?\DateTimeImmutable $lastNotifiedAt = null,
    ) {
    }

    public static function fromProvider(Sw6OidcProviderEntity $provider): self
    {
        $immutable = static fn (?\DateTimeInterface $date): ?\DateTimeImmutable => $date instanceof \DateTimeInterface ? \DateTimeImmutable::createFromInterface($date) : null;

        return new self(
            $provider->getHealthAlertConsecutiveFailures(),
            $provider->getHealthAlertLastStatus(),
            $immutable($provider->getHealthAlertFirstFailureAt()),
            $immutable($provider->getHealthAlertLastNotifiedAt()),
        );
    }

    /**
     * @return array{self, self::NOTIFY_*|null} the next state and what to notify (if anything)
     */
    public function next(bool $healthy, int $threshold, bool $notifyOnRecovery, \DateTimeImmutable $now): array
    {
        if ($healthy) {
            if ($notifyOnRecovery && $this->alertedCurrentOutage()) {
                return [new self(0, self::STATUS_RECOVERY_PENDING, $this->firstFailureAt, $this->lastNotifiedAt), self::NOTIFY_RECOVERED];
            }

            return [new self(0, self::STATUS_OK, null, $this->lastNotifiedAt), null];
        }

        $failures = $this->consecutiveFailures + 1;
        $firstFailureAt = $this->lastStatus === self::STATUS_FAIL && $this->firstFailureAt instanceof \DateTimeImmutable ? $this->firstFailureAt : $now;
        $next = new self($failures, self::STATUS_FAIL, $firstFailureAt, $this->lastNotifiedAt);

        $due = $threshold > 0
            && $failures >= $threshold
            && (!$this->lastNotifiedAt instanceof \DateTimeImmutable || $this->lastNotifiedAt < $firstFailureAt);

        return [$next, $due ? self::NOTIFY_UNHEALTHY : null];
    }

    /**
     * The notification of this state was delivered. A delivered recovery
     * notice closes the outage.
     */
    public function withNotifiedAt(\DateTimeImmutable $at): self
    {
        if ($this->lastStatus === self::STATUS_RECOVERY_PENDING) {
            return new self(0, self::STATUS_OK, null, $at);
        }

        return new self($this->consecutiveFailures, $this->lastStatus, $this->firstFailureAt, $at);
    }

    private function alertedCurrentOutage(): bool
    {
        return \in_array($this->lastStatus, [self::STATUS_FAIL, self::STATUS_RECOVERY_PENDING], true)
            && $this->firstFailureAt instanceof \DateTimeImmutable
            && $this->lastNotifiedAt instanceof \DateTimeImmutable
            && $this->lastNotifiedAt >= $this->firstFailureAt;
    }
}
