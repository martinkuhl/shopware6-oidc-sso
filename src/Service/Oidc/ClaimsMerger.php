<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;

/**
 * The id_token/userinfo rules shared by the login callback and the live
 * login test, so the test reports exactly what a real login would do (L5).
 */
final class ClaimsMerger
{
    public static function requestsOpenIdScope(string $scope): bool
    {
        return \in_array('openid', preg_split('/\s+/', trim($scope)) ?: [], true);
    }

    /**
     * Userinfo usually carries more claims and wins in general, but the
     * identity-defining claims come from the signed id_token (OIDC Core
     * §5.3.2): userinfo must describe the same subject, and `sub`, `email`
     * and `email_verified` are never taken from it when the id_token has them.
     *
     * @param array<string, mixed> $idTokenClaims
     * @param array<string, mixed> $userInfoClaims
     *
     * @return array<string, mixed>
     *
     * @throws InvalidStateException when userinfo describes another subject
     */
    public static function merge(array $idTokenClaims, array $userInfoClaims): array
    {
        $idTokenSub = $idTokenClaims['sub'] ?? null;

        if ($idTokenClaims !== [] && $userInfoClaims !== [] && ($userInfoClaims['sub'] ?? null) !== $idTokenSub) {
            throw new InvalidStateException('The userinfo response describes a different subject than the id_token.');
        }

        $merged = array_merge($idTokenClaims, $userInfoClaims);

        foreach (['sub', 'email', 'email_verified'] as $claim) {
            if (\array_key_exists($claim, $idTokenClaims)) {
                $merged[$claim] = $idTokenClaims[$claim];
            }
        }

        return $merged;
    }

    /**
     * Every login is bound to the subject, so merged claims without a `sub`
     * can't log anyone in — the live test applies the same rule (R3-L4).
     *
     * @param array<string, mixed> $mergedClaims
     *
     * @throws InvalidStateException
     */
    public static function requireSubject(array $mergedClaims): string
    {
        $sub = $mergedClaims['sub'] ?? null;

        if (!\is_string($sub) || $sub === '') {
            throw new InvalidStateException('The identity provider did not return a subject ("sub") claim.');
        }

        return $sub;
    }
}
