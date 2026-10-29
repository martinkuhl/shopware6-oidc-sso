<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Core\Content\Provider\Field;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Field\Sw6OidcEncryptedField;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Field\Sw6OidcEncryptedFieldSerializer;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Field;
use Shopware\Core\Framework\DataAbstractionLayer\FieldSerializer\FieldSerializerInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Write\DataStack\KeyValuePair;
use Shopware\Core\Framework\DataAbstractionLayer\Write\EntityExistence;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteParameterBag;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;

#[CoversClass(Sw6OidcEncryptedFieldSerializer::class)]
final class Sw6OidcEncryptedFieldSerializerTest extends TestCase
{
    private const PURPOSE = 'sw6oidc_provider.client_secret';

    private Sw6OidcEncryptor $encryptor;

    /** @var list<mixed> values the inner (string) serializer was asked to encode */
    private array $innerSaw = [];

    protected function setUp(): void
    {
        $this->encryptor = new Sw6OidcEncryptor('app-secret');
    }

    public function testEncodeEncryptsTheInnerSerializersOutput(): void
    {
        $out = $this->encode('  my-secret  ');

        self::assertSame(['  my-secret  '], $this->innerSaw);
        self::assertSame('my-secret', $this->encryptor->decrypt($out['client_secret'], self::PURPOSE));
        self::assertNull($this->encryptor->decryptOrNull($out['client_secret']), 'bound to its field');
    }

    public function testEncodeKeepsNull(): void
    {
        self::assertSame(['client_secret' => null], $this->encode(null));
    }

    public function testDecryptableEnvelopeIsReEncryptedFromPlaintext(): void
    {
        $out = $this->encode($this->encryptor->encrypt('from-export', self::PURPOSE));

        self::assertSame(['from-export'], $this->innerSaw, 'validation must see the plaintext');
        self::assertSame('from-export', $this->encryptor->decrypt($out['client_secret'], self::PURPOSE));
    }

    public function testEnvelopeOfAnotherFieldIsRejected(): void
    {
        $this->expectException(WriteConstraintViolationException::class);
        $this->encode($this->encryptor->encrypt('webhook', 'sw6oidc_provider.health_alert_webhook_url'));
    }

    public function testForeignEnvelopeIsRejected(): void
    {
        $foreign = (new Sw6OidcEncryptor('other-instance'))->encrypt('secret');

        $this->expectException(WriteConstraintViolationException::class);
        $this->encode($foreign);
    }

    public function testDecode(): void
    {
        $serializer = new Sw6OidcEncryptedFieldSerializer($this->createMock(FieldSerializerInterface::class), $this->encryptor);
        $field = new Sw6OidcEncryptedField('client_secret', 'clientSecret');

        self::assertSame('abc', $serializer->decode($field, $this->encryptor->encrypt('abc', self::PURPOSE)));
        self::assertSame('legacy', $serializer->decode($field, 'legacy'));
        self::assertNull($serializer->decode($field, null));
    }

    /**
     * @return array<string, ?string>
     */
    private function encode(?string $value): array
    {
        $inner = $this->createMock(FieldSerializerInterface::class);
        $inner->method('encode')->willReturnCallback(function (Field $field, EntityExistence $existence, KeyValuePair $data): \Generator {
            $this->innerSaw[] = $data->getValue();

            yield 'client_secret' => \is_string($data->getValue()) ? trim($data->getValue()) : null;
        });

        $serializer = new Sw6OidcEncryptedFieldSerializer($inner, $this->encryptor);
        $parameters = $this->createMock(WriteParameterBag::class);
        $parameters->method('getPath')->willReturn('/0');

        return iterator_to_array($serializer->encode(
            new Sw6OidcEncryptedField('client_secret', 'clientSecret', 1024),
            $this->createMock(EntityExistence::class),
            new KeyValuePair('clientSecret', $value, true),
            $parameters,
        ));
    }
}
