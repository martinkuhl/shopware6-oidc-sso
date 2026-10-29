<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\UserProvider;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class Sw6OidcUserProviderEntity extends Entity
{
    use EntityIdTrait;

    public const USER_TYPE_ADMIN = 'admin';
    public const USER_TYPE_CUSTOMER = 'customer';

    /** binding_scope of every admin and of customers not bound to a sales channel. */
    public const GLOBAL_SCOPE = '00000000000000000000000000000000';

    /** 'admin'|'customer' — the binding is polymorphic, so userId intentionally has no DAL association */
    protected string $userType;
    protected string $userId;
    protected string $providerId;
    protected ?string $issuer = null;
    protected ?string $sub = null;
    protected ?string $issuerHash = null;
    protected string $bindingScope = self::GLOBAL_SCOPE;

    protected ?Sw6OidcProviderEntity $provider = null;

    public function getUserType(): string
    {
        return $this->userType;
    }

    public function setUserType(string $userType): void
    {
        $this->userType = $userType;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function setUserId(string $userId): void
    {
        $this->userId = $userId;
    }

    public function getProviderId(): string
    {
        return $this->providerId;
    }

    public function setProviderId(string $providerId): void
    {
        $this->providerId = $providerId;
    }

    public function getProvider(): ?Sw6OidcProviderEntity
    {
        return $this->provider;
    }

    public function setProvider(?Sw6OidcProviderEntity $provider): void
    {
        $this->provider = $provider;
    }

    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    public function setIssuer(?string $issuer): void
    {
        $this->issuer = $issuer;
    }

    public function getSub(): ?string
    {
        return $this->sub;
    }

    public function getIssuerHash(): ?string
    {
        return $this->issuerHash;
    }

    public function setIssuerHash(?string $issuerHash): void
    {
        $this->issuerHash = $issuerHash;
    }

    /**
     * The sales channel a channel-bound customer's binding belongs to, else GLOBAL_SCOPE.
     */
    public function getBindingScope(): string
    {
        return $this->bindingScope;
    }

    public function setBindingScope(string $bindingScope): void
    {
        $this->bindingScope = $bindingScope;
    }

    public function setSub(?string $sub): void
    {
        $this->sub = $sub;
    }
}
