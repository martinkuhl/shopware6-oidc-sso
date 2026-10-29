<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;

/**
 * Everything needed to complete one SP-initiated OIDC round trip, stored
 * server-side under the opaque `state` value for the duration of the IdP
 * redirect (see OidcSecurityHelper).
 *
 * `purpose` says what the round trip is for: a normal login, an explicit
 * "Connect SSO" of an already logged-in account (`link`), or a fresh
 * re-authentication of the Administration (`step_up`) or the Storefront
 * (`reauth`). All but `login` carry the account that started the flow in
 * `expectedUserId`; the callback must act on exactly that account.
 */
final readonly class AuthorizationFlowContext
{
    public const PURPOSE_LOGIN = 'login';
    public const PURPOSE_LINK = 'link';
    public const PURPOSE_STEP_UP = 'step_up';
    public const PURPOSE_REAUTH = 'reauth';

    private const PURPOSES = [self::PURPOSE_LOGIN, self::PURPOSE_LINK, self::PURPOSE_STEP_UP, self::PURPOSE_REAUTH];
    private const LOGIN_TYPES = [LoginType::Customer->value, LoginType::Admin->value, LoginType::ProviderTest->value];

    public function __construct(
        public string $providerId,
        /** a LoginType value; ProviderTest is the live login test */
        public string $loginType,
        public string $relayState,
        public string $codeVerifier,
        /** 'S256' | 'plain' */
        public string $codeChallengeMethod,
        public string $nonce,
        public string $purpose = self::PURPOSE_LOGIN,
        public ?string $expectedUserId = null,
        /** unix time the flow started, for step-up `auth_time` checks */
        public int $startedAt = 0,
        /** BrowserBinding hash of the browser that started the flow (M1) */
        public ?string $browserBinding = null,
        /** UI locale of the admin running a live login test, for its result page */
        public ?string $locale = null,
    ) {
    }

    /**
     * @return array{
     *     providerId: string,
     *     loginType: string,
     *     relayState: string,
     *     codeVerifier: string,
     *     codeChallengeMethod: string,
     *     nonce: string,
     *     purpose: string,
     *     expectedUserId: string|null,
     *     startedAt: int,
     *     browserBinding: string|null,
     *     locale: string|null
     * }
     */
    public function toArray(): array
    {
        return [
            'providerId' => $this->providerId,
            'loginType' => $this->loginType,
            'relayState' => $this->relayState,
            'codeVerifier' => $this->codeVerifier,
            'codeChallengeMethod' => $this->codeChallengeMethod,
            'nonce' => $this->nonce,
            'purpose' => $this->purpose,
            'expectedUserId' => $this->expectedUserId,
            'startedAt' => $this->startedAt,
            'browserBinding' => $this->browserBinding,
            'locale' => $this->locale,
        ];
    }

    /**
     * @param array<mixed> $data
     *
     * @throws InvalidStateException when the stored flow is incomplete or malformed
     */
    public static function fromArray(array $data): self
    {
        foreach (['providerId', 'loginType', 'relayState', 'codeVerifier', 'codeChallengeMethod', 'nonce'] as $key) {
            if (!\is_string($data[$key] ?? null)) {
                throw new InvalidStateException(sprintf('Stored OAuth state is missing "%s".', $key));
            }
        }

        $purpose = $data['purpose'] ?? self::PURPOSE_LOGIN;
        $expectedUserId = $data['expectedUserId'] ?? null;
        $startedAt = $data['startedAt'] ?? 0;
        $browserBinding = $data['browserBinding'] ?? null;
        $locale = $data['locale'] ?? null;

        if (
            !\in_array($data['loginType'], self::LOGIN_TYPES, true)
            || !\in_array($purpose, self::PURPOSES, true)
            || ($expectedUserId !== null && !\is_string($expectedUserId))
            || !\is_int($startedAt)
            || ($browserBinding !== null && !\is_string($browserBinding))
            || ($locale !== null && !\is_string($locale))
            || ($purpose !== self::PURPOSE_LOGIN && $expectedUserId === null)
        ) {
            throw new InvalidStateException('Stored OAuth state is malformed.');
        }

        return new self(
            $data['providerId'],
            $data['loginType'],
            $data['relayState'],
            $data['codeVerifier'],
            $data['codeChallengeMethod'],
            $data['nonce'],
            $purpose,
            $expectedUserId,
            $startedAt,
            $browserBinding,
            $locale,
        );
    }
}
