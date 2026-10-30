<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The answer of every passkey options endpoint (admin, Storefront,
 * step-up): the ceremony's id and the WebAuthn options for the browser.
 */
final class CeremonyResponse
{
    /**
     * @param array{nonce: string, optionsJson: string} $ceremony
     */
    public static function options(array $ceremony): JsonResponse
    {
        return new JsonResponse(['sessionId' => $ceremony['nonce'], 'options' => json_decode($ceremony['optionsJson'], true)]);
    }
}
