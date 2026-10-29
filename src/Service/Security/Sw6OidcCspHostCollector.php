<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Service\Security;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use Psr\Cache\CacheItemPoolInterface;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;

/**
 * The deduplicated https origins (scheme://host[:port]) of every active
 * provider's endpoints — what a Content-Security-Policy would need to allow
 * for browser-side interaction with the IdPs. Cached in cache.app; the cache
 * is cleared whenever a provider is written (Sw6OidcCspSubscriber).
 */
class Sw6OidcCspHostCollector
{
    private const CACHE_KEY = 'sw6oidc_csp_hosts';

    /**
     * @param EntityRepository<Sw6OidcProviderCollection> $providerRepository
     */
    public function __construct(
        private readonly EntityRepository $providerRepository,
        private readonly CacheItemPoolInterface $cache,
    ) {
    }

    /**
     * @return list<string>
     */
    public function collect(Context $context): array
    {
        $item = $this->cache->getItem(self::CACHE_KEY);

        if ($item->isHit() && \is_array($item->get())) {
            /** @var list<string> */
            return $item->get();
        }

        $criteria = (new Criteria())->addFilter(new EqualsFilter('isActive', true));
        $origins = [];

        foreach ($this->providerRepository->search($criteria, $context)->getEntities() as $provider) {
            $urls = [
                $provider->getAuthorizeEndpoint(),
                $provider->getEndSessionEndpoint(),
                $provider->getAccessTokenEndpoint(),
                $provider->getUserInfoEndpoint(),
                $provider->getJwksEndpoint(),
                $provider->getRevocationEndpoint(),
                $provider->getWellKnownConfigUrl(),
            ];

            foreach ($urls as $url) {
                $origin = $this->httpsOrigin($url);

                if ($origin !== null) {
                    $origins[$origin] = true;
                }
            }
        }

        $origins = array_keys($origins);
        sort($origins);

        $item->set($origins);
        $this->cache->save($item);

        return $origins;
    }

    public function invalidate(): void
    {
        $this->cache->deleteItem(self::CACHE_KEY);
    }

    private function httpsOrigin(?string $url): ?string
    {
        $parts = $url !== null ? parse_url($url) : false;

        if (!\is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || !isset($parts['host']) || $parts['host'] === '') {
            return null;
        }

        return 'https://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
