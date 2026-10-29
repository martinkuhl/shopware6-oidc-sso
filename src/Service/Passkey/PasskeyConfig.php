<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Shopware\Core\System\SystemConfig\SystemConfigService;

/**
 * Global (non-provider-scoped) Passkey configuration — enable toggles + RP
 * name/id override, read from the plugin's own config.xml-backed system
 * config.
 */
class PasskeyConfig
{
    public const CONFIG_DOMAIN = 'Sw6Oidc.config.';
    /** Storefront RP ID, per sales channel (R3-M8). */
    public const KEY_RP_ID = self::CONFIG_DOMAIN . 'passkeyRpId';
    /** Administration RP ID, global (R3-M8). */
    public const KEY_RP_ID_ADMIN = self::CONFIG_DOMAIN . 'passkeyRpIdAdmin';

    public function __construct(private readonly SystemConfigService $systemConfigService)
    {
    }

    public function isEnabledForAdmin(): bool
    {
        return (bool) $this->systemConfigService->get(self::CONFIG_DOMAIN . 'passkeyEnabledAdmin');
    }

    public function isEnabledForCustomer(?string $salesChannelId = null): bool
    {
        return (bool) $this->systemConfigService->get(self::CONFIG_DOMAIN . 'passkeyEnabledCustomer', $salesChannelId);
    }

    public function getRpName(string $fallback): string
    {
        $configured = $this->stringValue($this->systemConfigService->get(self::CONFIG_DOMAIN . 'passkeyRpName'));

        return $configured !== '' ? $configured : $fallback;
    }

    /**
     * The Storefront RP ID of a sales channel: its own value, else the
     * global one, else the current domain's host. The Administration has a
     * value of its own (getAdminRpId()): the two often sit on different
     * registrable domains (R3-M8).
     */
    public function getRpId(string $fallbackHost, ?string $salesChannelId = null): string
    {
        $configured = $this->stringValue($this->systemConfigService->get(self::KEY_RP_ID, $salesChannelId));

        return $configured !== '' ? $configured : $fallbackHost;
    }

    public function getAdminRpId(string $fallbackHost): string
    {
        $configured = $this->stringValue($this->systemConfigService->get(self::KEY_RP_ID_ADMIN));

        return $configured !== '' ? $configured : $fallbackHost;
    }

    private function stringValue(mixed $value): string
    {
        return \is_string($value) ? trim($value) : '';
    }
}
