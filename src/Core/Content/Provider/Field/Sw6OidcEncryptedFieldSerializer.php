<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\Provider\Field;

use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Shopware\Core\Framework\DataAbstractionLayer\Field\Field;
use Shopware\Core\Framework\DataAbstractionLayer\Field\StorageAware;
use Shopware\Core\Framework\DataAbstractionLayer\FieldSerializer\FieldSerializerInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Write\DataStack\KeyValuePair;
use Shopware\Core\Framework\DataAbstractionLayer\Write\EntityExistence;
use Shopware\Core\Framework\DataAbstractionLayer\Write\WriteParameterBag;
use Shopware\Core\Framework\Validation\WriteConstraintViolationException;
use Symfony\Component\Validator\ConstraintViolation;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * Encrypts Sw6OidcEncryptedField values on write, decrypts on read. Wraps
 * (rather than extends — it's @internal) core's StringFieldSerializer, so
 * trimming, length and not-blank validation run against the plaintext
 * exactly as for a plain StringField.
 *
 * An already-encrypted envelope written back (e.g. a config import carrying
 * the stored value) is accepted only if it decrypts with this installation's
 * key — a blob from an instance with a different APP_SECRET is rejected
 * instead of being stored as an unusable secret.
 */
class Sw6OidcEncryptedFieldSerializer implements FieldSerializerInterface
{
    public const VIOLATION_UNDECRYPTABLE = 'SW6OIDC_SECRET_UNDECRYPTABLE';

    public function __construct(
        private readonly FieldSerializerInterface $stringFieldSerializer,
        private readonly Sw6OidcEncryptor $encryptor,
    ) {
    }

    public function normalize(Field $field, array $data, WriteParameterBag $parameters): array
    {
        return $this->stringFieldSerializer->normalize($field, $data, $parameters);
    }

    public function encode(Field $field, EntityExistence $existence, KeyValuePair $data, WriteParameterBag $parameters): \Generator
    {
        $value = $data->getValue();
        $purpose = self::purpose($field);

        if (\is_string($value) && $this->encryptor->isEncrypted($value)) {
            if (!$this->encryptor->canDecrypt($value, $purpose)) {
                $violations = new ConstraintViolationList([new ConstraintViolation(
                    'The encrypted secret cannot be decrypted with this installation\'s APP_SECRET. Provide the plaintext secret instead.',
                    null,
                    [],
                    $value,
                    '/' . $data->getKey(),
                    null,
                    null,
                    self::VIOLATION_UNDECRYPTABLE,
                )]);

                throw new WriteConstraintViolationException($violations, $parameters->getPath());
            }

            $data->setValue($this->encryptor->decrypt($value, $purpose));
        }

        foreach ($this->stringFieldSerializer->encode($field, $existence, $data, $parameters) as $storageName => $encoded) {
            yield $storageName => \is_string($encoded) ? $this->encryptor->encrypt($encoded, $purpose) : $encoded;
        }
    }

    public function decode(Field $field, mixed $value): ?string
    {
        return \is_string($value) ? $this->encryptor->decrypt($value, self::purpose($field)) : null;
    }

    /**
     * The encryption purpose (key + associated data) of a field: its entity
     * and storage name, so an envelope only decrypts where it was written.
     */
    public static function purpose(Field $field): string
    {
        return 'sw6oidc_provider.' . ($field instanceof StorageAware ? $field->getStorageName() : $field->getPropertyName());
    }
}
