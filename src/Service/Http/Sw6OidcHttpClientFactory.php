<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Http;

use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Builds the plugin's outbound HTTP clients. Each is wrapped in
 * NoPrivateNetworkHttpClient, which checks the *resolved* IP on every
 * connection and every redirect — closing the DNS rebinding / open-redirect
 * gaps a save-time URL check (SsrfUrlValidator) cannot.
 * SW6OIDC_ALLOW_INSECURE_IDP_URLS=1 disables the wrapper for local
 * development IdPs on private addresses.
 *
 * Redirects are off by default (M12): IdP endpoints are configured exactly,
 * and a redirect is more often an attack or a misconfiguration than a need.
 * A caller that must follow one (avatar CDNs) passes max_redirects per
 * request; every hop is still IP-checked.
 *
 * The option is set on the *outer* client: NoPrivateNetworkHttpClient
 * follows redirects itself with its own default (20) and ignores the inner
 * client's setting (R3-M2), so a 307 from the token endpoint would re-POST
 * the code and PKCE verifier to another host.
 *
 * Every response is capped: a hostile or broken endpoint can't make a login
 * buffer megabytes. The IdP client (token, userinfo, discovery, JWKS,
 * webhooks) and the user-content client (`picture` URLs, larger images) are
 * separate, each with its own cap.
 */
final class Sw6OidcHttpClientFactory
{
    public static function create(HttpClientInterface $inner, bool $allowInsecure, int $maxResponseBytes): HttpClientInterface
    {
        $client = $allowInsecure ? $inner : new NoPrivateNetworkHttpClient($inner);

        return $client->withOptions([
            'max_redirects' => 0,
            'on_progress' => static function (int $downloaded) use ($maxResponseBytes): void {
                if ($downloaded > $maxResponseBytes) {
                    throw new \RuntimeException(sprintf('Response larger than %d bytes.', $maxResponseBytes));
                }
            },
        ]);
    }
}
