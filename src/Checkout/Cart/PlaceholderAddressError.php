<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Checkout\Cart;

use Shopware\Core\Checkout\Cart\Error\Error;

/**
 * The customer's billing or shipping address still holds the placeholders a
 * JIT-created account got (M16): the order is blocked until it is completed.
 */
class PlaceholderAddressError extends Error
{
    public const KEY = 'sw6oidc-placeholder-address';

    public function __construct(private readonly string $addressId)
    {
        parent::__construct();
    }

    public function getId(): string
    {
        return self::KEY . '-' . $this->addressId;
    }

    public function getMessageKey(): string
    {
        return self::KEY;
    }

    public function getLevel(): int
    {
        return self::LEVEL_ERROR;
    }

    public function blockOrder(): bool
    {
        return true;
    }

    /**
     * Re-evaluated on every calculation, gone once the address is complete.
     */
    public function isPersistent(): bool
    {
        return false;
    }

    /**
     * @return array{addressId: string}
     */
    public function getParameters(): array
    {
        return ['addressId' => $this->addressId];
    }
}
