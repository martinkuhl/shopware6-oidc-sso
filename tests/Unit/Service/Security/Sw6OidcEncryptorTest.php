<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[CoversClass(Sw6OidcEncryptor::class)]
final class Sw6OidcEncryptorTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');
        $encrypted = $encryptor->encrypt('s3cr3t <with> "chars"');

        self::assertStringStartsWith(Sw6OidcEncryptor::PREFIX, $encrypted);
        self::assertStringNotContainsString('s3cr3t', $encrypted);
        self::assertSame('s3cr3t <with> "chars"', $encryptor->decrypt($encrypted));
        self::assertTrue($encryptor->canDecrypt($encrypted));
    }

    public function testEachEncryptionUsesAFreshNonce(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        self::assertNotSame($encryptor->encrypt('same'), $encryptor->encrypt('same'));
    }

    public function testLegacyPlaintextPassesThrough(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        self::assertSame('plain-legacy-secret', $encryptor->decrypt('plain-legacy-secret'));
        self::assertFalse($encryptor->isEncrypted('plain-legacy-secret'));
        self::assertFalse($encryptor->canDecrypt('plain-legacy-secret'));
    }

    public function testWrongKeyPassesThroughAndLogs(): void
    {
        $encrypted = (new Sw6OidcEncryptor('old-app-secret'))->encrypt('secret');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $encryptor = new Sw6OidcEncryptor('new-app-secret', $logger);

        self::assertSame($encrypted, $encryptor->decrypt($encrypted));
        self::assertFalse($encryptor->canDecrypt($encrypted));
    }

    public function testAnUndecryptableValueIsReportedOncePerRequest(): void
    {
        $envelope = (new Sw6OidcEncryptor('old-secret'))->encrypt('client-secret');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::exactly(2))->method('error');
        $encryptor = new Sw6OidcEncryptor('new-secret', $logger);

        // Every hydration decrypts again; one log line per request (R3-L42).
        $encryptor->decrypt($envelope);
        $encryptor->decrypt($envelope);
        $encryptor->reset();
        $encryptor->decrypt($envelope);
    }

    public function testCorruptEnvelopePassesThrough(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');

        foreach ([Sw6OidcEncryptor::PREFIX . '!!not-base64!!', Sw6OidcEncryptor::PREFIX . base64_encode('short')] as $corrupt) {
            self::assertSame($corrupt, $encryptor->decrypt($corrupt));
            self::assertFalse($encryptor->canDecrypt($corrupt));
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
        $envelope = $encryptor->encrypt('secret', 'sw6oidc_provider.client_secret');

        self::assertStringStartsWith(Sw6OidcEncryptor::PREFIX, $envelope);
        self::assertSame('secret', $encryptor->decryptOrNull($envelope, 'sw6oidc_provider.client_secret'));
        self::assertNull($encryptor->decryptOrNull($envelope, 'sw6oidc_provider.health_alert_webhook_url'));
        self::assertNull($encryptor->decryptOrNull($envelope));
        self::assertFalse($encryptor->canDecrypt($envelope, 'sw6oidc_one_time_token.value'));
    }

    public function testDecryptOrNullPassesPlaintextThroughAndNeverReturnsAnEnvelope(): void
    {
        $encryptor = new Sw6OidcEncryptor('app-secret');
        $foreign = (new Sw6OidcEncryptor('other'))->encrypt('secret');

        self::assertSame('plain', $encryptor->decryptOrNull('plain'));
        self::assertNull($encryptor->decryptOrNull($foreign));
        self::assertTrue(Sw6OidcEncryptor::isEnvelope($foreign));
        self::assertFalse(Sw6OidcEncryptor::isEnvelope('plain'));
    }

    public function testLegacyV1EnvelopesAreStillReadable(): void
    {
        // A v1 envelope as written by earlier releases (secretbox, one key).
        $key = sodium_crypto_generichash('app-secret' . "\0sw6oidc/client_secret/v1", '', \SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $legacy = Sw6OidcEncryptor::LEGACY_PREFIX . base64_encode($nonce . sodium_crypto_secretbox('old-secret', $nonce, $key));

        $encryptor = new Sw6OidcEncryptor('app-secret');

        self::assertTrue($encryptor->isLegacy($legacy));
        self::assertTrue(Sw6OidcEncryptor::isEnvelope($legacy));
        self::assertSame('old-secret', $encryptor->decrypt($legacy, 'sw6oidc_provider.client_secret'));
    }
}
