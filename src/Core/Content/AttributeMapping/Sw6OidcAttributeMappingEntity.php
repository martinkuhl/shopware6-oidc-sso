<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class Sw6OidcAttributeMappingEntity extends Entity
{
    use EntityIdTrait;

    protected string $providerId;
    protected string $attributeType;
    protected string $attributeName;
    protected ?string $transformFunction = null;
    /** @var array<string, mixed>|null */
    protected ?array $transformParams = null;

    protected ?Sw6OidcProviderEntity $provider = null;

    public function getProviderId(): string
    {
        return $this->providerId;
    }

    public function setProviderId(string $providerId): void
    {
        $this->providerId = $providerId;
    }

    public function getAttributeType(): string
    {
        return $this->attributeType;
    }

    public function setAttributeType(string $attributeType): void
    {
        $this->attributeType = $attributeType;
    }

    public function getAttributeName(): string
    {
        return $this->attributeName;
    }

    public function setAttributeName(string $attributeName): void
    {
        $this->attributeName = $attributeName;
    }

    public function getTransformFunction(): ?string
    {
        return $this->transformFunction;
    }

    public function setTransformFunction(?string $transformFunction): void
    {
        $this->transformFunction = $transformFunction;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getTransformParams(): ?array
    {
        return $this->transformParams;
    }

    /**
     * @param array<string, mixed>|null $transformParams
     */
    public function setTransformParams(?array $transformParams): void
    {
        $this->transformParams = $transformParams;
    }

    public function getProvider(): ?Sw6OidcProviderEntity
    {
        return $this->provider;
    }

    public function setProvider(?Sw6OidcProviderEntity $provider): void
    {
        $this->provider = $provider;
    }
}
