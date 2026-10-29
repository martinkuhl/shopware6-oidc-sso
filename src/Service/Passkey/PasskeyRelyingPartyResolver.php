<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use MartinKuhl\Sw6Oidc\Service\Passkey\Exception\PasskeyCeremonyException;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainEntity;
use Shopware\Core\System\SalesChannel\SalesChannelContext;

/**
 * Derives the relying party for a ceremony from configuration, never from
 * the request:
 *
 * - Administration: the origin of APP_URL; the RP ID is its host unless
 *   `passkeyRpId` is configured.
 * - Storefront: the origins of the current sales channel's domains; the RP ID
 *   is the current domain's host unless `passkeyRpId` is configured. Only
 *   origins whose host is the RP ID or a subdomain of it can be used with it
 *   (WebAuthn's registrable-suffix rule), so the others are dropped.
 *
 * The origins are pinned into each ceremony and checked exactly
 * (CheckAllowedOrigins without subdomains) — an assertion relayed through
 * another host of the RP ID's domain is refused (N-M1).
 */
class PasskeyRelyingPartyResolver
{
    public function __construct(
        private readonly PasskeyConfig $passkeyConfig,
        private readonly string $appUrl,
    ) {
    }

    /**
     * @throws PasskeyCeremonyException when APP_URL is unusable
     */
    public function forAdministration(): PasskeyRelyingParty
    {
        $origin = self::origin($this->appUrl);

        if ($origin === null) {
            throw new PasskeyCeremonyException('APP_URL is not an absolute URL; passkeys cannot be used in the Administration.');
        }

        $host = (string) parse_url($origin, PHP_URL_HOST);
        $rpId = $this->passkeyConfig->getAdminRpId($host);

        return new PasskeyRelyingParty($rpId, $this->passkeyConfig->getRpName('Shopware Administration'), $this->originsForRpId([$origin], $rpId));
    }

    /**
     * @throws PasskeyCeremonyException when the sales channel has no usable domain
     */
    public function forSalesChannel(SalesChannelContext $context): PasskeyRelyingParty
    {
        // Core loads the channel's domains into every context (R3-L19).
        $domains = $context->getSalesChannel()->getDomains();
        $urls = $domains instanceof SalesChannelDomainCollection ? array_values($domains->map(static fn (SalesChannelDomainEntity $domain): string => $domain->getUrl())) : [];

        $origins = array_values(array_unique(array_filter(array_map(self::origin(...), $urls))));

        $domainId = $context->getDomainId();
        $currentUrl = ($domainId !== null ? $domains?->get($domainId)?->getUrl() : null) ?? ($urls[0] ?? null);
        $currentHost = \is_string($currentUrl) ? (string) parse_url($currentUrl, PHP_URL_HOST) : '';

        if ($currentHost === '' || $origins === []) {
            throw new PasskeyCeremonyException('The sales channel has no domain to bind passkeys to.');
        }

        $rpId = $this->passkeyConfig->getRpId($currentHost, $context->getSalesChannelId());
        $name = $this->passkeyConfig->getRpName((string) ($context->getSalesChannel()->getTranslated()['name'] ?? 'Shop'));

        return new PasskeyRelyingParty($rpId, $name, $this->originsForRpId($origins, $rpId));
    }

    /**
     * Whether $rpId may serve as the WebAuthn RP ID for $host: the host
     * itself or one of its parent domains.
     */
    public static function covers(string $rpId, string $host): bool
    {
        $rpId = strtolower(trim($rpId));
        $host = strtolower($host);

        return $rpId !== '' && ($host === $rpId || str_ends_with($host, '.' . $rpId));
    }

    /**
     * scheme://host[:port] of an absolute http(s) URL, or null.
     */
    public static function origin(string $url): ?string
    {
        $parts = parse_url($url);

        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host']) || !\in_array(strtolower($parts['scheme']), ['https', 'http'], true)) {
            return null;
        }

        return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }

    /**
     * @param list<string> $origins
     *
     * @return list<string>
     */
    private function originsForRpId(array $origins, string $rpId): array
    {
        $rpId = strtolower($rpId);

        return array_values(array_filter(
            $origins,
            static fn (string $origin): bool => self::covers($rpId, (string) parse_url($origin, PHP_URL_HOST)),
        ));
    }
}
