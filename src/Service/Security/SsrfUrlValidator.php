<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * SSRF check for every admin-supplied URL the plugin will fetch server-side
 * (discovery, token, userinfo, JWKS, revocation, ...): HTTPS only, and the
 * host must not resolve to a private, loopback, link-local or otherwise
 * reserved address (Symfony's IpUtils::PRIVATE_SUBNETS, plus multicast — the
 * same list NoPrivateNetworkHttpClient enforces at request time).
 *
 * SW6OIDC_ALLOW_INSECURE_IDP_URLS=1 ($allowInsecure) relaxes both rules for
 * development setups (a local/docker IdP over plain HTTP on a private IP):
 * such URLs are then allowed with a warning. Unresolvable hosts are blocked
 * either way.
 */
class SsrfUrlValidator
{
    /** @var \Closure(string): list<string> */
    private readonly \Closure $resolver;

    /**
     * @param (\Closure(string): list<string>)|null $resolver host => IPs; defaults to DNS (A + AAAA)
     */
    public function __construct(
        private readonly bool $allowInsecure = false,
        ?\Closure $resolver = null,
    ) {
        $this->resolver = $resolver ?? $this->resolveViaDns(...);
    }


    /**
     * @return array{blocked: bool, warnings: list<string>}
     */
    public function validate(string $url): array
    {
        $parts = parse_url($url);

        if ($parts === false || !isset($parts['host'], $parts['scheme'])) {
            return ['blocked' => true, 'warnings' => ['The URL is not valid.']];
        }

        $scheme = strtolower($parts['scheme']);

        if (!\in_array($scheme, ['http', 'https'], true)) {
            return ['blocked' => true, 'warnings' => [sprintf('Unsupported URL scheme "%s"; only https is allowed.', $parts['scheme'])]];
        }

        $warnings = [];

        if ($scheme === 'http') {
            if (!$this->allowInsecure) {
                return ['blocked' => true, 'warnings' => ['Only https URLs are allowed (set SW6OIDC_ALLOW_INSECURE_IDP_URLS=1 to allow plain http in development).']];
            }

            $warnings[] = 'This URL uses plain HTTP; traffic to it is not encrypted in transit.';
        }

        $host = trim($parts['host'], '[]');
        $ips = ($this->resolver)($host);

        if ($ips === []) {
            // An unresolvable host fails on its own anyway, but it is also what
            // a malformed/spoofed SSRF attempt looks like — block, don't pass.
            return ['blocked' => true, 'warnings' => ['The host of this URL could not be resolved.']];
        }

        foreach ($ips as $ip) {
            if (!$this->isPublicIp($ip)) {
                if (!$this->allowInsecure) {
                    return ['blocked' => true, 'warnings' => [
                        'This URL resolves to a private, loopback, or otherwise non-public address and cannot be used '
                        . '(set SW6OIDC_ALLOW_INSECURE_IDP_URLS=1 to allow this in development).',
                    ]];
                }

                $warnings[] = 'This URL resolves to a private or loopback address (allowed because SW6OIDC_ALLOW_INSECURE_IDP_URLS is enabled).';

                break;
            }
        }

        return ['blocked' => false, 'warnings' => $warnings];
    }

    private function isPublicIp(string $ip): bool
    {
        if (filter_var($ip, \FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return !IpUtils::isPrivateIp($ip) && !IpUtils::checkIp($ip, ['224.0.0.0/4', 'ff00::/8']);
    }

    /**
     * @return list<string>
     */
    private function resolveViaDns(string $host): array
    {
        if (filter_var($host, \FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];
        $ipv4 = gethostbynamel($host);

        if (\is_array($ipv4)) {
            $ips = $ipv4;
        }

        $aaaaRecords = @dns_get_record($host, \DNS_AAAA);

        if (\is_array($aaaaRecords)) {
            foreach ($aaaaRecords as $record) {
                if (isset($record['ipv6']) && \is_string($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        return $ips;
    }
}
