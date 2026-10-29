<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\SessionActivity;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class Sw6OidcSessionActivityEntity extends Entity
{
    use EntityIdTrait;

    protected ?string $providerId = null;
    /** 'customer' | 'admin' */
    protected string $userType;
    protected string $userId;
    protected ?string $sub = null;
    protected ?string $sid = null;
    /** 'oidc' | 'passkey' */
    protected string $loginMethod;
    protected ?string $sessionKeyHash = null;
    protected ?string $registrySessionId = null;
    protected ?string $passkeyCredentialHash = null;
    protected ?string $ipAddress = null;
    protected ?string $userAgent = null;
    protected \DateTimeInterface $loggedInAt;
    protected ?\DateTimeInterface $loggedOutAt = null;
    protected ?string $logoutReason = null;

    protected ?Sw6OidcProviderEntity $provider = null;

    public function getProviderId(): ?string
    {
        return $this->providerId;
    }

    public function getUserType(): string
    {
        return $this->userType;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getSub(): ?string
    {
        return $this->sub;
    }

    public function getSid(): ?string
    {
        return $this->sid;
    }

    public function getLoginMethod(): string
    {
        return $this->loginMethod;
    }

    public function getSessionKeyHash(): ?string
    {
        return $this->sessionKeyHash;
    }

    public function getRegistrySessionId(): ?string
    {
        return $this->registrySessionId;
    }

    public function getPasskeyCredentialHash(): ?string
    {
        return $this->passkeyCredentialHash;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function getLoggedInAt(): \DateTimeInterface
    {
        return $this->loggedInAt;
    }

    public function getLoggedOutAt(): ?\DateTimeInterface
    {
        return $this->loggedOutAt;
    }

    public function getLogoutReason(): ?string
    {
        return $this->logoutReason;
    }

    public function getProvider(): ?Sw6OidcProviderEntity
    {
        return $this->provider;
    }
}
