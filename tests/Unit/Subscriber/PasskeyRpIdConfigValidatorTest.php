<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Subscriber;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\ParameterType;
use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyConfigException;
use MartinKuhl\Sw6Oidc\Service\Passkey\PasskeyConfig;
use MartinKuhl\Sw6Oidc\Subscriber\PasskeyRpIdConfigValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SystemConfig\Event\BeforeSystemConfigChangedEvent;

/**
 * R3-M8: an RP ID that can't work where it applies is refused on save.
 */
#[CoversClass(PasskeyRpIdConfigValidator::class)]
final class PasskeyRpIdConfigValidatorTest extends TestCase
{
    private Connection $connection;

    private string $german;

    private string $english;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $this->connection->executeStatement('CREATE TABLE `sales_channel_domain` (`sales_channel_id` BLOB, `url` TEXT)');
        $this->german = $this->channel(['https://shop.example.de', 'https://www.shop.example.de']);
        $this->english = $this->channel(['https://shop.example.com']);
    }

    public function testAdministrationRpIdMustCoverTheAppUrlHost(): void
    {
        $this->validate(PasskeyConfig::KEY_RP_ID_ADMIN, 'example.com');
        $this->validate(PasskeyConfig::KEY_RP_ID_ADMIN, 'admin.example.com');
        $this->validate(PasskeyConfig::KEY_RP_ID_ADMIN, '');

        $this->expectException(PasskeyConfigException::class);
        $this->validate(PasskeyConfig::KEY_RP_ID_ADMIN, 'example.de');
    }

    public function testChannelRpIdMustCoverOneOfItsDomains(): void
    {
        $this->validate(PasskeyConfig::KEY_RP_ID, 'example.de', $this->german);

        $this->expectException(PasskeyConfigException::class);
        $this->validate(PasskeyConfig::KEY_RP_ID, 'example.de', $this->english);
    }

    public function testGlobalRpIdMustCoverEveryChannel(): void
    {
        $this->expectException(PasskeyConfigException::class);
        $this->validate(PasskeyConfig::KEY_RP_ID, 'example.de');
    }

    public function testOtherKeysAreIgnored(): void
    {
        $this->expectNotToPerformAssertions();
        $this->validate('Sw6Oidc.config.passkeyRpName', 'anything');
    }

    private function validate(string $key, string $value, ?string $salesChannelId = null): void
    {
        (new PasskeyRpIdConfigValidator($this->connection, 'https://admin.example.com/'))
            ->validate(new BeforeSystemConfigChangedEvent($key, $value, $salesChannelId));
    }

    /**
     * @param list<string> $urls
     */
    private function channel(array $urls): string
    {
        $id = Uuid::randomHex();

        foreach ($urls as $url) {
            $this->connection->insert('sales_channel_domain', ['sales_channel_id' => Uuid::fromHexToBytes($id), 'url' => $url], ['sales_channel_id' => ParameterType::BINARY]);
        }

        return $id;
    }
}
