<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Passkey\Exception;

use Shopware\Core\Framework\HttpException;
use Symfony\Component\HttpFoundation\Response;

class PasskeyConfigException extends HttpException
{
    public const RP_ID_INVALID = 'SW6OIDC_PASSKEY_RP_ID_INVALID';

    /**
     * @param list<string> $hosts
     */
    public static function rpIdDoesNotCoverHosts(string $rpId, array $hosts): self
    {
        return new self(
            Response::HTTP_BAD_REQUEST,
            self::RP_ID_INVALID,
            'The passkey Relying Party ID "{{ rpId }}" must be the host, or a parent domain of the host, of {{ hosts }}.',
            ['rpId' => $rpId, 'hosts' => implode(', ', $hosts)],
        );
    }
}
