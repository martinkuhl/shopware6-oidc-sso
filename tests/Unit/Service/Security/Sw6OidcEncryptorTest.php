<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[CoversClass(Sw6OidcEncryptor::class)]
final class Sw6OidcEncryptorTest extends TestCase
{
    private const PURPOSE = 'sw6oidc_provider.client_secret';

    public function testRoundTrip(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');
        $encrypted = $encryptor->encrypt('s3cr3t <with> "chars"', self::PURPOSE);

        self::assertStringStartsWith(Sw6OidcEncryptor::PREFIX, $encrypted);
        self::assertStringNotContainsString('s3cr3t', $encrypted);
        self::assertSame('s3cr3t <with> "chars"', $encryptor->decrypt($encrypted, self::PURPOSE));
        self::assertTrue($encryptor->canDecrypt($encrypted, self::PURPOSE));
    }

    public function testEachEncryptionUsesAFreshNonce(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        self::assertNotSame($encryptor->encrypt('same', self::PURPOSE), $encryptor->encrypt('same', self::PURPOSE));
    }

    public function testAValueThatIsNoEnvelopeIsNeverTreatedAsDecrypted(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        self::assertNull($encryptor->decryptOrNull('plain', self::PURPOSE));
        self::assertFalse($encryptor->canDecrypt('plain', self::PURPOSE));
        // Hydration still never breaks.
        self::assertSame('plain', $encryptor->decrypt('plain', self::PURPOSE));
    }

    public function testWrongKeyPassesThroughAndLogs(): void
    {
        $encrypted = (new Sw6OidcEncryptor('old-app-secret'))->encrypt('secret', self::PURPOSE);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $encryptor = new Sw6OidcEncryptor('new-app-secret', $logger);

        self::assertSame($encrypted, $encryptor->decrypt($encrypted, self::PURPOSE));
        self::assertFalse($encryptor->canDecrypt($encrypted, self::PURPOSE));
    }

    public function testAnUndecryptableValueIsReportedOncePerRequest(): void
    {
        $envelope = (new Sw6OidcEncryptor('old-secret'))->encrypt('client-secret', self::PURPOSE);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::exactly(2))->method('error');
        $encryptor = new Sw6OidcEncryptor('new-secret', $logger);

        // Every hydration decrypts again; one log line per request (R3-L42).
        $encryptor->decrypt($envelope, self::PURPOSE);
        $encryptor->decrypt($envelope, self::PURPOSE);
        $encryptor->reset();
        $encryptor->decrypt($envelope, self::PURPOSE);
    }

    public function testCorruptEnvelopePassesThrough(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        foreach ([Sw6OidcEncryptor::PREFIX . '!!not-base64!!', Sw6OidcEncryptor::PREFIX . base64_encode('short')] as $corrupt) {
            self::assertSame($corrupt, $encryptor->decrypt($corrupt, self::PURPOSE));
            self::assertFalse($encryptor->canDecrypt($corrupt, self::PURPOSE));
        }
    }

    public function testEmptyAppSecretIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Sw6OidcEncryptor('');
    }

    public function testPurposeBindsTheEnvelope(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');
        $envelope = $encryptor->encrypt('secret', self::PURPOSE);

        self::assertSame('secret', $encryptor->decryptOrNull($envelope, self::PURPOSE));
        self::assertNull($encryptor->decryptOrNull($envelope, 'sw6oidc_provider.health_alert_webhook_url'));
        self::assertFalse($encryptor->canDecrypt($envelope, 'sw6oidc_one_time_token.value'));
    }

    public function testDecryptOrNullNeverReturnsAnEnvelope(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');
        $foreign = (new Sw6OidcEncryptor('other'))->encrypt('secret', self::PURPOSE);

        self::assertNull($encryptor->decryptOrNull($foreign, self::PURPOSE));
        self::assertTrue(Sw6OidcEncryptor::isEnvelope($foreign));
        self::assertFalse(Sw6OidcEncryptor::isEnvelope('plain'));
    }
}
