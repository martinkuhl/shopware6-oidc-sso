<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Subscriber;

use MartinKuhl\Sw6Oidc\Service\Security\Sw6OidcCspHostCollector;
use Shopware\Core\Framework\Context;
use Shopware\Core\PlatformRequest;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Makes an existing Content-Security-Policy allow the active IdPs.
 *
 * Shopware 6.7 has no CSP contribution API: core's CoreSubscriber sets the
 * header from the fixed `shopware.security.csp_templates` (storefront: empty
 * by default, administration: script/object/base-uri/frame-ancestors only).
 * This runs after it and only *appends* the IdP origins to the directives
 * that could concern an IdP (form-action, connect-src, frame-src, img-src)
 * **if they are already present** — it never adds a directive (that would
 * tighten the policy) and never touches a directive whose value is 'none'.
 *
 * With the stock templates this is a no-op: every IdP interaction is a
 * top-level navigation or server-side call. It matters for shops that ship
 * their own stricter policy (e.g. `form-action 'self'`).
 */
class Sw6OidcCspSubscriber implements EventSubscriberInterface
{
    private const HEADER = 'Content-Security-Policy';
    private const REPORT_ONLY_HEADER = 'Content-Security-Policy-Report-Only';

    private const DIRECTIVES = ['form-action', 'connect-src', 'frame-src', 'img-src'];

    private const SCOPES = ['storefront', 'administration'];

    public function __construct(private readonly Sw6OidcCspHostCollector $hostCollector)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // After core's CoreSubscriber::setSecurityHeaders() (priority 0).
            KernelEvents::RESPONSE => ['onResponse', -10],
            'sw6oidc_provider.written' => 'onProviderWritten',
            'sw6oidc_provider.deleted' => 'onProviderWritten',
        ];
    }

    public function onProviderWritten(): void
    {
        $this->hostCollector->invalidate();
    }

    public function onResponse(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        $headers = array_filter(
            [self::HEADER, self::REPORT_ONLY_HEADER],
            $response->headers->has(...),
        );

        if ($headers === []) {
            return;
        }

        $scopes = $event->getRequest()->attributes->get(PlatformRequest::ATTRIBUTE_ROUTE_SCOPE, []);

        if (!\is_array($scopes) || array_intersect($scopes, self::SCOPES) === []) {
            return;
        }

        $hosts = $this->hostCollector->collect(Context::createDefaultContext());

        if ($hosts === []) {
            return;
        }

        // Every policy header (several may be set; each one must allow a
        // request) and the Report-Only variant are extended alike (N-L15).
        foreach ($headers as $header) {
            $policies = array_map(
                static fn (?string $policy): string => self::appendHosts((string) $policy, $hosts),
                $response->headers->all(strtolower($header)),
            );

            $response->headers->set($header, array_values(array_filter($policies, static fn (string $policy): bool => $policy !== '')));
        }
    }

    /**
     * @param list<string> $hosts
     */
    public static function appendHosts(string $policy, array $hosts): string
    {
        $directives = [];

        foreach (explode(';', $policy) as $directive) {
            $directive = trim($directive);

            if ($directive === '') {
                continue;
            }

            $tokens = preg_split('/\s+/', $directive) ?: [];
            $name = strtolower($tokens[0]);

            if (\in_array($name, self::DIRECTIVES, true) && !\in_array("'none'", $tokens, true)) {
                foreach ($hosts as $host) {
                    if (!\in_array($host, $tokens, true)) {
                        $tokens[] = $host;
                    }
                }
            }

            $directives[] = implode(' ', $tokens);
        }

        return implode('; ', $directives);
    }
}
