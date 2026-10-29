<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

/**
 * Where a WebAuthn ceremony may happen: the RP ID credentials are bound to,
 * the name shown by the authenticator, and the exact origins (scheme + host
 * + port) whose clientData the plugin accepts — no subdomains, no Host-header
 * guessing.
 */
final readonly class PasskeyRelyingParty
{
    /**
     * @param list<string> $origins
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $origins,
    ) {
    }
}
