<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\ScheduledTask;

use MartinKuhl\Sw6Oidc\Service\Health\ProviderHealthMonitor;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\MessageQueue\ScheduledTask\ScheduledTaskHandler;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler(handles: HealthCheckAlertTask::class)]
class HealthCheckAlertTaskHandler extends ScheduledTaskHandler
{
    public function __construct(
        EntityRepository $scheduledTaskRepository,
        LoggerInterface $exceptionLogger,
        private readonly ProviderHealthMonitor $monitor,
    ) {
        parent::__construct($scheduledTaskRepository, $exceptionLogger);
    }

    /**
     * No node heartbeat here: the worker isn't a web node, and counting it
     * reported every one-web-node setup as multi-node (R3-L32).
     */
    public function run(): void
    {
        $this->monitor->run();
    }
}
