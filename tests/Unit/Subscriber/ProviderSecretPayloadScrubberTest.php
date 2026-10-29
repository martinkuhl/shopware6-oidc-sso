<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use MartinKuhl\Sw6Oidc\Subscriber\ProviderSecretPayloadScrubber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityWriteResult;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;

#[CoversClass(ProviderSecretPayloadScrubber::class)]
final class ProviderSecretPayloadScrubberTest extends TestCase
{
    public function testSecretsAreBlankedAndOtherFieldsKept(): void
    {
        $event = new EntityWrittenEvent('sw6oidc_provider', [
            new EntityWriteResult('id-1', ['id' => 'id-1', 'clientSecret' => 'plain', 'healthAlertWebhookUrl' => 'https://hooks.example/T/abc', 'appName' => 'Dex'], 'sw6oidc_provider', EntityWriteResult::OPERATION_UPDATE),
            new EntityWriteResult('id-2', ['id' => 'id-2', 'appName' => 'Other'], 'sw6oidc_provider', EntityWriteResult::OPERATION_UPDATE),
        ], Context::createDefaultContext());

        // Prime the lazy payload cache, as an earlier reader would.
        $event->getPayloads();

        (new ProviderSecretPayloadScrubber())->onProviderWritten($event);

        self::assertSame(
            [
                ['id' => 'id-1', 'clientSecret' => '', 'healthAlertWebhookUrl' => '', 'appName' => 'Dex'],
                ['id' => 'id-2', 'appName' => 'Other'],
            ],
            $event->getPayloads(),
        );
        self::assertSame(EntityWriteResult::OPERATION_UPDATE, $event->getWriteResults()[0]->getOperation());
    }

    public function testRunsBeforeEveryOtherListener(): void
    {
        self::assertSame(['onProviderWritten', \PHP_INT_MAX], ProviderSecretPayloadScrubber::getSubscribedEvents()['sw6oidc_provider.written']);
    }
}
