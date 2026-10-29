<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\UserProvider\Sw6OidcUserProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Provisioning\UserProviderBindingService;
use MartinKuhl\Sw6Oidc\Service\Security\SsoOnlyInvariant;
use MartinKuhl\Sw6Oidc\Service\Security\UserVerifiedScope;
use Psr\Log\LoggerInterface;
use Shopware\Core\Framework\Api\Context\AdminApiSource;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsAnyFilter;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Framework\Uuid\Uuid;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Read/unlink access to sw6oidc_user_provider for the Administration's
 * user and customer pages - the "OIDC Provider" info row and its "Unlink
 * IdP" button.
 *
 * A dedicated endpoint rather than the generic entity API because the
 * binding's userId is polymorphic (no DAL association to user/customer), and
 * because ordinary ACL roles have no privilege on sw6oidc_user_provider
 * itself: access is instead gated by the core user.* / customer.* privileges
 * of whichever account type is being looked at, checked per request since it
 * depends on the userType parameter.
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class OidcUserProviderAdminController extends AbstractController
{
    private const MAX_IDS = 500;

    private const PRIVILEGE_PREFIX = [
        Sw6OidcUserProviderEntity::USER_TYPE_ADMIN => 'user',
        Sw6OidcUserProviderEntity::USER_TYPE_CUSTOMER => 'customer',
    ];

    /**
     * @param EntityRepository<Sw6OidcUserProviderCollection> $userProviderRepository
     */
    public function __construct(
        private readonly EntityRepository $userProviderRepository,
        private readonly UserProviderBindingService $bindingService,
        private readonly LoggerInterface $logger,
        private readonly SsoOnlyInvariant $ssoOnlyInvariant,
    ) {
    }

    #[Route(path: '/api/_action/sw6oidc/user-provider/info', name: 'api.action.sw6oidc.user-provider.info', methods: ['POST'])]
    public function info(Request $request, Context $context): JsonResponse
    {
        $userType = (string) $request->request->get('userType', '');

        if (!isset(self::PRIVILEGE_PREFIX[$userType])) {
            return new JsonResponse(['error' => 'invalid_request', 'message' => 'Unknown userType.'], 400);
        }

        $userIds = $this->parseUserIds($request);

        if (!$this->isAllowed($context, self::PRIVILEGE_PREFIX[$userType] . ':read')) {
            // Any admin may read their own binding (profile page), even
            // without user:read on other accounts.
            $source = $context->getSource();
            $ownId = $source instanceof AdminApiSource ? $source->getUserId() : null;

            if ($userType !== Sw6OidcUserProviderEntity::USER_TYPE_ADMIN || $ownId === null || $userIds !== [$ownId]) {
                return new JsonResponse(['error' => 'forbidden'], 403);
            }
        }

        if ($userIds === []) {
            return new JsonResponse(['bindings' => new \stdClass()]);
        }

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('userType', $userType));
        $criteria->addFilter(new EqualsAnyFilter('userId', $userIds));
        $criteria->addAssociation('provider');

        $bindings = [];

        foreach ($this->userProviderRepository->search($criteria, $context)->getEntities() as $binding) {
            $provider = $binding->getProvider();

            $bindings[$binding->getUserId()] = [
                'providerId' => $binding->getProviderId(),
                'providerName' => $provider instanceof Sw6OidcProviderEntity ? ($provider->getDisplayName() ?: $provider->getAppName()) : null,
                'createdAt' => $binding->getCreatedAt()?->format(\DateTimeInterface::ATOM),
            ];
        }

        return new JsonResponse(['bindings' => $bindings === [] ? new \stdClass() : $bindings]);
    }

    #[Route(path: '/api/_action/sw6oidc/user-provider/unlink', name: 'api.action.sw6oidc.user-provider.unlink', methods: ['POST'])]
    public function unlink(Request $request, Context $context): Response
    {
        $userType = (string) $request->request->get('userType', '');
        $userId = strtolower((string) $request->request->get('userId', ''));

        if (!isset(self::PRIVILEGE_PREFIX[$userType]) || !Uuid::isValid($userId)) {
            return new JsonResponse(['error' => 'invalid_request', 'message' => 'A valid userType and userId are required.'], 400);
        }

        if (!$this->isAllowed($context, self::PRIVILEGE_PREFIX[$userType] . ':update')) {
            return new JsonResponse(['error' => 'forbidden'], 403);
        }

        if ($userType === Sw6OidcUserProviderEntity::USER_TYPE_ADMIN) {
            // Core requires a re-authenticated token for any user change; an
            // unlink can lock an admin out, so it needs the same (R3-H7).
            if (!UserVerifiedScope::isPresent($request)) {
                return new JsonResponse(['error' => 'user_verification_required'], 403);
            }

            if (!$this->ssoOnlyInvariant->holds(unboundUserIds: [$userId]) && $this->ssoOnlyInvariant->holds()) {
                return new JsonResponse([
                    'error' => 'last_sso_admin',
                    'message' => 'Administration password login is disabled and this is the last admin who can log in through single sign-on.',
                ], 409);
            }
        }

        // System scope: the acting role was checked above, but it holds no
        // write privilege on sw6oidc_user_provider itself (AclWriteValidator).
        $context->scope(Context::SYSTEM_SCOPE, fn (Context $systemContext) => $this->bindingService->unbind($userType, $userId, $systemContext));

        $source = $context->getSource();
        $this->logger->info('sw6oidc: unlinked account from its OIDC provider via the Administration.', [
            'userType' => $userType,
            'userId' => $userId,
            'actingUserId' => $source instanceof AdminApiSource ? $source->getUserId() : null,
        ]);

        return new Response(null, Response::HTTP_NO_CONTENT);
    }

    private function isAllowed(Context $context, string $privilege): bool
    {
        $source = $context->getSource();

        return $source instanceof AdminApiSource && $source->isAllowed($privilege);
    }

    /**
     * Accepts either a comma-separated string (form-encoded, as the
     * Administration's fetch helper sends) or a real array (JSON body).
     *
     * @return list<string>
     */
    private function parseUserIds(Request $request): array
    {
        $raw = $request->request->all()['userIds'] ?? [];

        if (\is_string($raw)) {
            $raw = explode(',', $raw);
        }

        if (!\is_array($raw)) {
            return [];
        }

        $ids = [];

        foreach ($raw as $id) {
            $id = strtolower(trim((string) $id));

            if (Uuid::isValid($id)) {
                $ids[$id] = $id;
            }
        }

        return \array_slice(array_values($ids), 0, self::MAX_IDS);
    }
}
