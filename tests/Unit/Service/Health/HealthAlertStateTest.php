<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Health;

use MartinKuhl\Sw6Oidc\Service\Health\HealthAlertState;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HealthAlertState::class)]
final class HealthAlertStateTest extends TestCase
{
    public function testAlertFiresOnceWhenTheThresholdIsCrossed(): void
    {
        $state = new HealthAlertState();
        $notifications = [];

        for ($minute = 0; $minute < 6; ++$minute) {
            [$state, $notify] = $state->next(false, 3, false, $this->at($minute));

            if ($notify !== null) {
                $notifications[] = [$minute, $notify];
                $state = $state->withNotifiedAt($this->at($minute));
            }
        }

        self::assertSame([[2, HealthAlertState::NOTIFY_UNHEALTHY]], $notifications);
        self::assertSame(6, $state->consecutiveFailures);
        self::assertEquals($this->at(0), $state->firstFailureAt, 'the outage start is kept');
    }

    public function testUndeliveredAlertIsRetriedNextRound(): void
    {
        [$state, $notify] = (new HealthAlertState())->next(false, 1, false, $this->at(0));
        self::assertSame(HealthAlertState::NOTIFY_UNHEALTHY, $notify);

        // Not marked as sent (webhook failed) -> due again.
        [, $notify] = $state->next(false, 1, false, $this->at(1));
        self::assertSame(HealthAlertState::NOTIFY_UNHEALTHY, $notify);
    }

    public function testLoweringTheThresholdMidOutageDoesNotReFire(): void
    {
        [$state] = (new HealthAlertState())->next(false, 2, false, $this->at(0));
        [$state, $notify] = $state->next(false, 2, false, $this->at(1));
        self::assertSame(HealthAlertState::NOTIFY_UNHEALTHY, $notify);
        $state = $state->withNotifiedAt($this->at(1));

        // Admin edits the provider: threshold 2 -> 1. The state is untouched by that edit.
        [, $notify] = $state->next(false, 1, false, $this->at(2));
        self::assertNull($notify);
    }

    public function testRecoveryNoticeOnlyAfterAnAlertAndOnlyWhenEnabled(): void
    {
        [$alerted] = (new HealthAlertState())->next(false, 1, true, $this->at(0));
        $alerted = $alerted->withNotifiedAt($this->at(0));

        [$recovered, $notify] = $alerted->next(true, 1, true, $this->at(1));
        self::assertSame(HealthAlertState::NOTIFY_RECOVERED, $notify);
        self::assertSame(HealthAlertState::STATUS_RECOVERY_PENDING, $recovered->lastStatus, 'until the notice is delivered');

        $delivered = $recovered->withNotifiedAt($this->at(1));
        self::assertSame([0, HealthAlertState::STATUS_OK, null], [$delivered->consecutiveFailures, $delivered->lastStatus, $delivered->firstFailureAt]);
        self::assertNull($delivered->next(true, 1, true, $this->at(2))[1], 'sent once');

        self::assertNull($alerted->next(true, 1, false, $this->at(1))[1], 'recovery notice disabled');

        [$failedOnce] = (new HealthAlertState())->next(false, 3, true, $this->at(0));
        self::assertNull($failedOnce->next(true, 3, true, $this->at(1))[1], 'no alert was sent, so no recovery notice');
    }

    /**
     * R8-L17: a recovery notice the webhook rejected is sent again on the
     * next healthy run, not dropped.
     */
    public function testAnUndeliveredRecoveryNoticeIsRetried(): void
    {
        [$alerted] = (new HealthAlertState())->next(false, 1, true, $this->at(0));
        $alerted = $alerted->withNotifiedAt($this->at(0));

        [$pending, $first] = $alerted->next(true, 1, true, $this->at(1));
        self::assertSame(HealthAlertState::NOTIFY_RECOVERED, $first);

        // Not delivered: $pending is persisted as is.
        [, $again] = $pending->next(true, 1, true, $this->at(2));
        self::assertSame(HealthAlertState::NOTIFY_RECOVERED, $again);
    }

    public function testANewOutageAlertsAgain(): void
    {
        [$state] = (new HealthAlertState())->next(false, 1, false, $this->at(0));
        $state = $state->withNotifiedAt($this->at(0));
        [$state] = $state->next(true, 1, false, $this->at(1));

        [, $notify] = $state->next(false, 1, false, $this->at(5));
        self::assertSame(HealthAlertState::NOTIFY_UNHEALTHY, $notify);
    }

    public function testThresholdZeroNeverAlerts(): void
    {
        $state = new HealthAlertState();

        for ($minute = 0; $minute < 5; ++$minute) {
            [$state, $notify] = $state->next(false, 0, true, $this->at($minute));
            self::assertNull($notify);
        }
    }

    private function at(int $minutes): \DateTimeImmutable
    {
        return new \DateTimeImmutable(sprintf('2026-01-01 10:%02d:00', $minutes));
    }
}
