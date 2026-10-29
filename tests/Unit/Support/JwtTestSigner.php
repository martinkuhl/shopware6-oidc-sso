<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Tests\Unit\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Signs test id_tokens with a throwaway key (RS256 by default, PS256 or
 * ES256 on request) and exposes the matching JWKS.
 */
final class JwtTestSigner
{
    public readonly JWK $key;

    public function __construct(string $kid = 'test-key', public readonly string $alg = 'RS256')
    {
        $parameters = ['kid' => $kid, 'alg' => $alg, 'use' => 'sig'];
        $this->key = $alg === 'ES256'
            ? JWKFactory::createECKey('P-256', $parameters)
            : JWKFactory::createRSAKey(2048, $parameters);
    }

    public function jwksJson(): string
    {
        return json_encode(new JWKSet([$this->key->toPublic()]), \JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $extraHeader additional protected header parameters
     */
    public function sign(array $claims, array $extraHeader = []): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new RS256(), new PS256(), new ES256()])))
            ->create()
            ->withPayload(json_encode($claims, \JSON_THROW_ON_ERROR))
            ->addSignature($this->key, ['alg' => $this->alg, 'kid' => $this->key->get('kid')] + $extraHeader)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function signHs256(array $claims): string
    {
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256']);
        $jws = (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->create()
            ->withPayload(json_encode($claims, \JSON_THROW_ON_ERROR))
            ->addSignature($key, ['alg' => 'HS256'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
