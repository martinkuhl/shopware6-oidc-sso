<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Core\Content\Provider;

use MartinKuhl\Sw6Oidc\Core\Content\AccessControlRule\Sw6OidcAccessControlRuleCollection;
use MartinKuhl\Sw6Oidc\Core\Content\AttributeMapping\Sw6OidcAttributeMappingCollection;
use MartinKuhl\Sw6Oidc\Core\Content\RoleMapping\Sw6OidcRoleMappingCollection;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerGroup\CustomerGroupEntity;
use Shopware\Core\Framework\Api\Acl\Role\AclRoleEntity;
use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcEncryptor;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class Sw6OidcProviderEntity extends Entity
{
    use EntityIdTrait;

    protected string $appName;
    protected ?string $displayName = null;
    protected string $clientId;
    protected ?string $clientSecret = null;
    protected ?string $authorizeEndpoint = null;
    protected ?string $accessTokenEndpoint = null;
    protected ?string $userInfoEndpoint = null;
    protected ?string $endSessionEndpoint = null;
    /** where the IdP sends the user after RP-initiated logout; null = the login page of the flow */
    protected ?string $postLogoutUrl = null;
    protected ?string $revocationEndpoint = null;
    protected ?string $jwksEndpoint = null;
    protected ?string $issuer = null;
    protected ?string $wellKnownConfigUrl = null;
    protected string $scope = 'openid profile email';
    protected string $pkceFlow = 'S256';
    protected bool $publicClient = false;
    protected string $groupAttribute = 'groups';
    protected bool $autoCreateCustomer = true;
    protected bool $autoCreateAdmin = false;
    protected bool $disableNonOidcAdminLogin = false;
    protected bool $disableNonOidcCustomerLogin = false;
    protected bool $showCustomerLink = true;
    protected bool $showAdminLink = true;
    protected bool $isActive = true;
    /** 'customer'|'admin'|'both' */
    protected string $loginType = 'both';
    protected int $sortOrder = 0;
    protected bool $syncCustomerProfileOnSso = false;
    protected bool $syncCustomerAddressOnSso = false;
    protected bool $syncCustomerGroupOnSso = false;
    protected bool $syncAdminProfileOnSso = false;
    protected bool $syncAdminRoleOnSso = false;
    /**
     * Explicit, separate opt-in gate for `sw6oidc_role_mapping` rows of type
     * 'superadmin' — even an accidentally-added superadmin mapping row has
     * no effect unless this is also on, so granting full Shopware superadmin
     * via OIDC group membership always requires two deliberate steps.
     */
    protected bool $allowSuperadminGroupMapping = false;
    protected bool $requireEmailVerified = true;
    protected bool $linkExistingAccounts = false;
    protected bool $frontchannelAdminLogout = false;

    /** @var list<string>|null */
    protected ?array $base64Claims = null;
    protected bool $revokeSuperadminOnSso = false;
    protected string $logoutStyle = Sw6OidcProviderDefinition::LOGOUT_STYLE_STANDARD;
    protected string $tokenEndpointAuthMethod = Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_BASIC;
    protected string $revocationEndpointAuthMethod = Sw6OidcProviderDefinition::CLIENT_AUTH_METHOD_BASIC;
    protected int $httpTimeout = 30;
    protected int $jwksCacheTtl = 86400;
    /** 'pass'|'fail'|'warning'|null (never tested) — set only by the live login test */
    protected ?string $lastTestStatus = null;
    protected ?\DateTimeInterface $lastTestAt = null;
    /** @var array<string, mixed>|null flattened claims received on the last live login test, keyed by claim name */
    protected ?array $lastTestClaims = null;
    protected ?string $healthAlertWebhookUrl = null;
    /** 0 = alerting off */
    protected int $healthAlertFailureThreshold = 0;
    protected bool $healthAlertNotifyOnRecovery = false;
    protected int $healthAlertConsecutiveFailures = 0;
    /** 'ok' | 'fail' | null (never probed) */
    protected ?string $healthAlertLastStatus = null;
    protected ?\DateTimeInterface $healthAlertLastCheckedAt = null;
    protected ?\DateTimeInterface $healthAlertFirstFailureAt = null;
    protected ?\DateTimeInterface $healthAlertLastNotifiedAt = null;
    protected ?string $defaultCustomerGroupId = null;
    protected ?string $defaultAclRoleId = null;

    protected ?Sw6OidcAttributeMappingCollection $attributeMappings = null;
    protected ?Sw6OidcRoleMappingCollection $roleMappings = null;
    protected ?Sw6OidcAccessControlRuleCollection $accessControlRules = null;
    protected ?CustomerGroupEntity $defaultCustomerGroup = null;
    protected ?AclRoleEntity $defaultAclRole = null;

    public function getAppName(): string
    {
        return $this->appName;
    }

    public function setAppName(string $appName): void
    {
        $this->appName = $appName;
    }

    public function getDisplayName(): ?string
    {
        return $this->displayName;
    }

    public function setDisplayName(?string $displayName): void
    {
        $this->displayName = $displayName;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setClientId(string $clientId): void
    {
        $this->clientId = $clientId;
    }

    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    public function setClientSecret(?string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }

    public function getAuthorizeEndpoint(): ?string
    {
        return $this->authorizeEndpoint;
    }

    public function setAuthorizeEndpoint(?string $authorizeEndpoint): void
    {
        $this->authorizeEndpoint = $authorizeEndpoint;
    }

    public function getAccessTokenEndpoint(): ?string
    {
        return $this->accessTokenEndpoint;
    }

    public function setAccessTokenEndpoint(?string $accessTokenEndpoint): void
    {
        $this->accessTokenEndpoint = $accessTokenEndpoint;
    }

    public function getUserInfoEndpoint(): ?string
    {
        return $this->userInfoEndpoint;
    }

    public function setUserInfoEndpoint(?string $userInfoEndpoint): void
    {
        $this->userInfoEndpoint = $userInfoEndpoint;
    }

    public function getEndSessionEndpoint(): ?string
    {
        return $this->endSessionEndpoint;
    }

    public function setEndSessionEndpoint(?string $endSessionEndpoint): void
    {
        $this->endSessionEndpoint = $endSessionEndpoint;
    }

    public function getHealthAlertWebhookUrl(): ?string
    {
        return $this->healthAlertWebhookUrl;
    }

    public function setHealthAlertWebhookUrl(?string $healthAlertWebhookUrl): void
    {
        $this->healthAlertWebhookUrl = $healthAlertWebhookUrl;
    }

    public function getHealthAlertFailureThreshold(): int
    {
        return $this->healthAlertFailureThreshold;
    }

    public function setHealthAlertFailureThreshold(int $healthAlertFailureThreshold): void
    {
        $this->healthAlertFailureThreshold = $healthAlertFailureThreshold;
    }

    public function isHealthAlertNotifyOnRecovery(): bool
    {
        return $this->healthAlertNotifyOnRecovery;
    }

    public function setHealthAlertNotifyOnRecovery(bool $healthAlertNotifyOnRecovery): void
    {
        $this->healthAlertNotifyOnRecovery = $healthAlertNotifyOnRecovery;
    }

    public function getHealthAlertConsecutiveFailures(): int
    {
        return $this->healthAlertConsecutiveFailures;
    }

    public function getHealthAlertLastStatus(): ?string
    {
        return $this->healthAlertLastStatus;
    }

    public function getHealthAlertLastCheckedAt(): ?\DateTimeInterface
    {
        return $this->healthAlertLastCheckedAt;
    }

    public function getHealthAlertFirstFailureAt(): ?\DateTimeInterface
    {
        return $this->healthAlertFirstFailureAt;
    }

    public function getHealthAlertLastNotifiedAt(): ?\DateTimeInterface
    {
        return $this->healthAlertLastNotifiedAt;
    }

    public function getPostLogoutUrl(): ?string
    {
        return $this->postLogoutUrl;
    }

    public function setPostLogoutUrl(?string $postLogoutUrl): void
    {
        $this->postLogoutUrl = $postLogoutUrl;
    }

    public function getRevocationEndpoint(): ?string
    {
        return $this->revocationEndpoint;
    }

    public function setRevocationEndpoint(?string $revocationEndpoint): void
    {
        $this->revocationEndpoint = $revocationEndpoint;
    }

    public function getJwksEndpoint(): ?string
    {
        return $this->jwksEndpoint;
    }

    public function setJwksEndpoint(?string $jwksEndpoint): void
    {
        $this->jwksEndpoint = $jwksEndpoint;
    }

    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    public function setIssuer(?string $issuer): void
    {
        $this->issuer = $issuer;
    }

    public function getWellKnownConfigUrl(): ?string
    {
        return $this->wellKnownConfigUrl;
    }

    public function setWellKnownConfigUrl(?string $wellKnownConfigUrl): void
    {
        $this->wellKnownConfigUrl = $wellKnownConfigUrl;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function setScope(string $scope): void
    {
        $this->scope = $scope;
    }

    public function getPkceFlow(): string
    {
        return $this->pkceFlow;
    }

    public function setPkceFlow(string $pkceFlow): void
    {
        $this->pkceFlow = $pkceFlow;
    }

    public function isPublicClient(): bool
    {
        return $this->publicClient;
    }

    public function setPublicClient(bool $publicClient): void
    {
        $this->publicClient = $publicClient;
    }

    public function getGroupAttribute(): string
    {
        return $this->groupAttribute;
    }

    public function setGroupAttribute(string $groupAttribute): void
    {
        $this->groupAttribute = $groupAttribute;
    }

    public function isAutoCreateCustomer(): bool
    {
        return $this->autoCreateCustomer;
    }

    public function setAutoCreateCustomer(bool $autoCreateCustomer): void
    {
        $this->autoCreateCustomer = $autoCreateCustomer;
    }

    public function isAutoCreateAdmin(): bool
    {
        return $this->autoCreateAdmin;
    }

    public function setAutoCreateAdmin(bool $autoCreateAdmin): void
    {
        $this->autoCreateAdmin = $autoCreateAdmin;
    }

    public function isDisableNonOidcAdminLogin(): bool
    {
        return $this->disableNonOidcAdminLogin;
    }

    public function setDisableNonOidcAdminLogin(bool $disableNonOidcAdminLogin): void
    {
        $this->disableNonOidcAdminLogin = $disableNonOidcAdminLogin;
    }

    public function isDisableNonOidcCustomerLogin(): bool
    {
        return $this->disableNonOidcCustomerLogin;
    }

    public function setDisableNonOidcCustomerLogin(bool $disableNonOidcCustomerLogin): void
    {
        $this->disableNonOidcCustomerLogin = $disableNonOidcCustomerLogin;
    }

    public function isShowCustomerLink(): bool
    {
        return $this->showCustomerLink;
    }

    public function setShowCustomerLink(bool $showCustomerLink): void
    {
        $this->showCustomerLink = $showCustomerLink;
    }

    public function isShowAdminLink(): bool
    {
        return $this->showAdminLink;
    }

    public function setShowAdminLink(bool $showAdminLink): void
    {
        $this->showAdminLink = $showAdminLink;
    }

    public function isActive(): bool
    {
        return $this->isActive;
    }

    public function setIsActive(bool $isActive): void
    {
        $this->isActive = $isActive;
    }

    public function getLoginType(): string
    {
        return $this->loginType;
    }

    public function setLoginType(string $loginType): void
    {
        $this->loginType = $loginType;
    }

    public function getSortOrder(): int
    {
        return $this->sortOrder;
    }

    public function setSortOrder(int $sortOrder): void
    {
        $this->sortOrder = $sortOrder;
    }

    public function isSyncCustomerProfileOnSso(): bool
    {
        return $this->syncCustomerProfileOnSso;
    }

    public function setSyncCustomerProfileOnSso(bool $syncCustomerProfileOnSso): void
    {
        $this->syncCustomerProfileOnSso = $syncCustomerProfileOnSso;
    }

    public function isSyncCustomerAddressOnSso(): bool
    {
        return $this->syncCustomerAddressOnSso;
    }

    public function setSyncCustomerAddressOnSso(bool $syncCustomerAddressOnSso): void
    {
        $this->syncCustomerAddressOnSso = $syncCustomerAddressOnSso;
    }

    public function isSyncCustomerGroupOnSso(): bool
    {
        return $this->syncCustomerGroupOnSso;
    }

    public function setSyncCustomerGroupOnSso(bool $syncCustomerGroupOnSso): void
    {
        $this->syncCustomerGroupOnSso = $syncCustomerGroupOnSso;
    }

    public function isSyncAdminProfileOnSso(): bool
    {
        return $this->syncAdminProfileOnSso;
    }

    public function setSyncAdminProfileOnSso(bool $syncAdminProfileOnSso): void
    {
        $this->syncAdminProfileOnSso = $syncAdminProfileOnSso;
    }

    public function isSyncAdminRoleOnSso(): bool
    {
        return $this->syncAdminRoleOnSso;
    }

    public function setSyncAdminRoleOnSso(bool $syncAdminRoleOnSso): void
    {
        $this->syncAdminRoleOnSso = $syncAdminRoleOnSso;
    }

    public function isAllowSuperadminGroupMapping(): bool
    {
        return $this->allowSuperadminGroupMapping;
    }

    public function setAllowSuperadminGroupMapping(bool $allowSuperadminGroupMapping): void
    {
        $this->allowSuperadminGroupMapping = $allowSuperadminGroupMapping;
    }

    public function getHttpTimeout(): int
    {
        return $this->httpTimeout;
    }

    public function setHttpTimeout(int $httpTimeout): void
    {
        $this->httpTimeout = $httpTimeout;
    }

    public function getJwksCacheTtl(): int
    {
        return $this->jwksCacheTtl;
    }

    public function setJwksCacheTtl(int $jwksCacheTtl): void
    {
        $this->jwksCacheTtl = $jwksCacheTtl;
    }

    public function getLastTestStatus(): ?string
    {
        return $this->lastTestStatus;
    }

    public function setLastTestStatus(?string $lastTestStatus): void
    {
        $this->lastTestStatus = $lastTestStatus;
    }

    public function getLastTestAt(): ?\DateTimeInterface
    {
        return $this->lastTestAt;
    }

    public function setLastTestAt(?\DateTimeInterface $lastTestAt): void
    {
        $this->lastTestAt = $lastTestAt;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getLastTestClaims(): ?array
    {
        return $this->lastTestClaims;
    }

    /**
     * @param array<string, mixed>|null $lastTestClaims
     */
    public function setLastTestClaims(?array $lastTestClaims): void
    {
        $this->lastTestClaims = $lastTestClaims;
    }

    public function getDefaultCustomerGroupId(): ?string
    {
        return $this->defaultCustomerGroupId;
    }

    public function setDefaultCustomerGroupId(?string $defaultCustomerGroupId): void
    {
        $this->defaultCustomerGroupId = $defaultCustomerGroupId;
    }

    public function getDefaultAclRoleId(): ?string
    {
        return $this->defaultAclRoleId;
    }

    public function setDefaultAclRoleId(?string $defaultAclRoleId): void
    {
        $this->defaultAclRoleId = $defaultAclRoleId;
    }

    public function getAttributeMappings(): ?Sw6OidcAttributeMappingCollection
    {
        return $this->attributeMappings;
    }

    public function setAttributeMappings(Sw6OidcAttributeMappingCollection $attributeMappings): void
    {
        $this->attributeMappings = $attributeMappings;
    }

    public function getRoleMappings(): ?Sw6OidcRoleMappingCollection
    {
        return $this->roleMappings;
    }

    public function setRoleMappings(Sw6OidcRoleMappingCollection $roleMappings): void
    {
        $this->roleMappings = $roleMappings;
    }

    public function getAccessControlRules(): ?Sw6OidcAccessControlRuleCollection
    {
        return $this->accessControlRules;
    }

    public function setAccessControlRules(Sw6OidcAccessControlRuleCollection $accessControlRules): void
    {
        $this->accessControlRules = $accessControlRules;
    }

    public function getDefaultCustomerGroup(): ?CustomerGroupEntity
    {
        return $this->defaultCustomerGroup;
    }

    public function setDefaultCustomerGroup(?CustomerGroupEntity $defaultCustomerGroup): void
    {
        $this->defaultCustomerGroup = $defaultCustomerGroup;
    }

    public function getDefaultAclRole(): ?AclRoleEntity
    {
        return $this->defaultAclRole;
    }

    public function setDefaultAclRole(?AclRoleEntity $defaultAclRole): void
    {
        $this->defaultAclRole = $defaultAclRole;
    }

    public function isRequireEmailVerified(): bool
    {
        return $this->requireEmailVerified;
    }

    public function setRequireEmailVerified(bool $requireEmailVerified): void
    {
        $this->requireEmailVerified = $requireEmailVerified;
    }

    public function isLinkExistingAccounts(): bool
    {
        return $this->linkExistingAccounts;
    }

    public function setLinkExistingAccounts(bool $linkExistingAccounts): void
    {
        $this->linkExistingAccounts = $linkExistingAccounts;
    }

    /**
     * Claim names whose values are base64-encoded ("*" = all). A name covers
     * the claim and everything nested under it.
     *
     * @return list<string>
     */
    public function getBase64Claims(): array
    {
        return array_values(array_filter(
            array_map(static fn (mixed $claim): string => \is_string($claim) ? trim($claim) : '', $this->base64Claims ?? []),
            static fn (string $claim): bool => $claim !== '',
        ));
    }

    /**
     * @param list<string>|null $base64Claims
     */
    public function setBase64Claims(?array $base64Claims): void
    {
        $this->base64Claims = $base64Claims;
    }

    public function isFrontchannelAdminLogout(): bool
    {
        return $this->frontchannelAdminLogout;
    }

    public function setFrontchannelAdminLogout(bool $frontchannelAdminLogout): void
    {
        $this->frontchannelAdminLogout = $frontchannelAdminLogout;
    }

    public function isRevokeSuperadminOnSso(): bool
    {
        return $this->revokeSuperadminOnSso;
    }

    public function setRevokeSuperadminOnSso(bool $revokeSuperadminOnSso): void
    {
        $this->revokeSuperadminOnSso = $revokeSuperadminOnSso;
    }

    public function getLogoutStyle(): string
    {
        return $this->logoutStyle;
    }

    public function setLogoutStyle(string $logoutStyle): void
    {
        $this->logoutStyle = $logoutStyle;
    }

    public function getTokenEndpointAuthMethod(): string
    {
        return $this->tokenEndpointAuthMethod;
    }

    public function setTokenEndpointAuthMethod(string $tokenEndpointAuthMethod): void
    {
        $this->tokenEndpointAuthMethod = $tokenEndpointAuthMethod;
    }

    public function getRevocationEndpointAuthMethod(): string
    {
        return $this->revocationEndpointAuthMethod;
    }

    public function setRevocationEndpointAuthMethod(string $revocationEndpointAuthMethod): void
    {
        $this->revocationEndpointAuthMethod = $revocationEndpointAuthMethod;
    }

    /**
     * The decrypted client secret, or null when it is empty or could not be
     * decrypted (hydration passes an undecryptable envelope through). Use
     * this wherever the secret is about to be sent or exported, so
     * ciphertext is never used as if it were the secret (N-L5).
     */
    public function getUsableClientSecret(): ?string
    {
        return $this->clientSecret === null || $this->clientSecret === '' || Sw6OidcEncryptor::isEnvelope($this->clientSecret)
            ? null
            : $this->clientSecret;
    }
}
