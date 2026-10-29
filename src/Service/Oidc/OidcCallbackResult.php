<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Oidc;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\ExternalIdentity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\MappedProfile;
use MartinKuhl\Sw6Oidc\Service\Security\AuthorizationFlowContext;
use Shopware\Core\Checkout\Customer\Service\EmailIdnConverter;

final readonly class OidcCallbackResult
{
    /**
     * @param array<string, mixed> $tokens raw token endpoint response (access_token, id_token, refresh_token, expires_in, ...)
     * @param array<string, mixed> $idTokenClaims verified id_token claims ([] when the IdP sent no id_token)
     * @param array<string, mixed> $claims id_token claims merged with userinfo claims (unflattened)
     */
    public function __construct(
        public Sw6OidcProviderEntity $provider,
        public AuthorizationFlowContext $flow,
        public MappedProfile $profile,
        public array $tokens,
        public array $idTokenClaims = [],
        public array $claims = [],
    ) {
    }

    public function idToken(): ?string
    {
        return $this->token('id_token');
    }

    public function idpAccessToken(): ?string
    {
        return $this->token('access_token');
    }

    public function idpRefreshToken(): ?string
    {
        return $this->token('refresh_token');
    }

    private function token(string $name): ?string
    {
        $value = $this->tokens[$name] ?? null;

        return \is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The IdP subject: from the verified id_token, else (providers without
     * the openid scope) from userinfo. The processor rejects a mismatch.
     */
    private function subject(): ?string
    {
        foreach ([$this->idTokenClaims['sub'] ?? null, $this->claims['sub'] ?? null] as $sub) {
            if (\is_string($sub) && $sub !== '') {
                return $sub;
            }
        }

        return null;
    }

    /**
     * The IdP session id (`sid`, OIDC Front-/Back-Channel Logout), only
     * trusted from the verified id_token.
     */
    public function sessionId(): ?string
    {
        $sid = $this->idTokenClaims['sid'] ?? null;

        return \is_string($sid) && $sid !== '' ? $sid : null;
    }

    /**
     * Whether the IdP vouches for the email this login maps to: the standard
     * `email_verified` claim is true (boolean, or the string "true" some IdPs
     * send) *and* the mapped email is the standard `email` claim it refers to.
     * An email mapped from a custom claim is never considered verified.
     */
    public function emailVerified(): bool
    {
        $verified = $this->claims['email_verified'] ?? null;
        $email = $this->claims['email'] ?? null;

        return ($verified === true || $verified === 'true')
            && \is_string($email)
            && strcasecmp(EmailIdnConverter::encode(trim($email)), $this->profile->email) === 0;
    }

    /**
     * @throws \LogicException when called without a subject (the processor guarantees one)
     */
    public function identity(): ExternalIdentity
    {
        $subject = $this->subject();

        if ($subject === null) {
            throw new \LogicException('OIDC callback result has no subject.');
        }

        $issuer = $this->idTokenClaims['iss'] ?? null;

        return new ExternalIdentity(
            $this->provider->getId(),
            \is_string($issuer) && $issuer !== '' ? $issuer : (string) $this->provider->getIssuer(),
            $subject,
            $this->profile->email,
            $this->emailVerified(),
        );
    }
}
