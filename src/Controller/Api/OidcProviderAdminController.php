<?php declare(strict_types=1);

namespace MartinKuhl\Sw6Oidc\Controller\Api;

use Doctrine\DBAL\Connection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderCollection;
use MartinKuhl\Sw6Oidc\Core\Content\Provider\Sw6OidcProviderEntity;
use MartinKuhl\Sw6Oidc\Service\Http\Exception\OidcHttpException;
use MartinKuhl\Sw6Oidc\Service\Oidc\AuthorizationRequestBuilder;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcConnectionTestService;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcDiscoveryService;
use MartinKuhl\Sw6Oidc\Service\Oidc\OidcLiveLoginTestService;
use MartinKuhl\Sw6Oidc\Service\Oidc\TestResultTranslator;
use MartinKuhl\Sw6Oidc\Service\Security\Exception\InvalidStateException;
use MartinKuhl\Sw6Oidc\Service\Security\LoginType;
use MartinKuhl\Sw6Oidc\Service\Security\OidcSecurityHelper;
use MartinKuhl\Sw6Oidc\Service\Security\PublicError;
use MartinKuhl\Sw6Oidc\Service\Security\SsrfUrlValidator;
use MartinKuhl\Sw6Oidc\Subscriber\Sw6OidcProviderWriteGuardSubscriber;
use Psr\Log\LoggerInterface;
use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\PlatformRequest;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Admin-management actions for sw6oidc_provider: on-demand well-known
 * auto-discovery, a fast synchronous connection/completeness check, and a
 * full live OIDC login round-trip test — all separate from
 * OidcAdminAuthController, which is deliberately auth_required:false at the
 * class level as a pre-auth login bridge and shouldn't also carry normal
 * ACL-gated management actions.
 *
 * Every action but testCallback() requires a normal authenticated
 * Administration session (default auth_required: true) gated by the
 * sw6oidc_provider.* privileges the module already declares. testCallback()
 * is necessarily anonymous — like the real admin OIDC callback, the browser
 * returning from the IdP carries no Administration bearer token — mirroring
 * the mixed-auth pattern PasskeyAdminController already uses for its
 * login-options/login-verify actions.
 */
#[Route(defaults: ['_routeScope' => ['api']])]
class OidcProviderAdminController extends AbstractController
{
    private const MAX_STORED_CLAIM_KEYS = 500;
    private const DEFAULT_TEST_TIMEOUT_SECONDS = 10;
    private const MAX_TEST_TIMEOUT_SECONDS = 30;

    /**
     * @param EntityRepository<Sw6OidcProviderCollection> $providerRepository
     */
    public function __construct(
        private readonly EntityRepository $providerRepository,
        private readonly AuthorizationRequestBuilder $requestBuilder,
        private readonly OidcSecurityHelper $securityHelper,
        private readonly OidcDiscoveryService $discoveryService,
        private readonly SsrfUrlValidator $urlValidator,
        private readonly OidcConnectionTestService $connectionTestService,
        private readonly OidcLiveLoginTestService $liveLoginTestService,
        private readonly LoggerInterface $logger,
        private readonly TestResultTranslator $translator,
        private readonly ?Connection $connection = null,
    ) {
    }

    /**
     * What the provider form needs from the server: the storefront
     * post-logout landing URLs (one per storefront domain — the admin's own
     * origin is usually not one, F-N15) and whether a webhook URL is stored
     * for this provider (it's write-only, F-N6).
     */
    #[Route(
        path: '/api/_action/sw6oidc/provider/form-context',
        name: 'api.action.sw6oidc.provider.form-context',
        defaults: ['_acl' => ['sw6oidc_provider:read']],
        methods: ['GET'],
    )]
    public function formContext(Request $request, Context $context): JsonResponse
    {
        $providerId = (string) $request->query->get('providerId', '');
        $provider = Uuid::isValid($providerId) ? $this->loadProvider($providerId, $context) : null;

        return new JsonResponse([
            'postLogoutLandingUrls' => $this->postLogoutLandingUrls(),
            'webhookConfigured' => $provider instanceof Sw6OidcProviderEntity && (string) $provider->getHealthAlertWebhookUrl() !== '',
        ]);
    }

    /**
     * @return list<string>
     */
    private function postLogoutLandingUrls(): array
    {
        if (!$this->connection instanceof Connection) {
            return [];
        }

        $urls = $this->connection->fetchFirstColumn(
            'SELECT DISTINCT domain.`url` FROM `sales_channel_domain` domain
             INNER JOIN `sales_channel` channel ON channel.`id` = domain.`sales_channel_id`
             WHERE channel.`type_id` = :storefront AND channel.`active` = 1
             ORDER BY domain.`url`',
            ['storefront' => Uuid::fromHexToBytes(Defaults::SALES_CHANNEL_TYPE_STOREFRONT)],
        );

        return array_values(array_map(
            static fn (mixed $url): string => rtrim((string) $url, '/') . '/sw6oidc/postlogout',
            array_filter($urls, static fn (mixed $url): bool => \is_string($url) && $url !== ''),
        ));
    }

    #[Route(
        path: '/api/_action/sw6oidc/provider/discover',
        name: 'api.action.sw6oidc.provider.discover',
        defaults: ['_acl' => ['sw6oidc_provider:update']],
        methods: ['POST'],
    )]
    public function discover(Request $request): JsonResponse
    {
        $wellKnownConfigUrl = $this->stringInput($request, 'wellKnownConfigUrl') ?? '';

        if ($wellKnownConfigUrl === '') {
            return new JsonResponse(['error' => 'invalid_request', 'message' => 'A well-known configuration URL is required.'], 400);
        }

        $timeout = $this->timeoutInput($request);

        $violation = $this->urlValidator->validate($wellKnownConfigUrl);

        if ($violation['blocked']) {
            return new JsonResponse(['error' => 'discovery_failed', 'message' => implode(' ', $violation['warnings'])], 400);
        }

        try {
            $endpoints = $this->discoveryService->discover($wellKnownConfigUrl, $timeout);
        } catch (OidcHttpException $exception) {
            return PublicError::response($this->logger, 'sw6oidc: discovery request failed.', $exception, 'discovery_failed', Response::HTTP_BAD_REQUEST);
        }

        $warnings = $violation['warnings'];
        $algorithmWarning = OidcDiscoveryService::unsupportedSigningAlgorithmsWarning($endpoints['idTokenSigningAlgValuesSupported'] ?? null);
        unset($endpoints['idTokenSigningAlgValuesSupported']);

        if ($algorithmWarning !== null) {
            $warnings[] = $algorithmWarning;
        }

        return new JsonResponse(array_merge($endpoints, ['warnings' => $warnings]));
    }

    #[Route(
        path: '/api/_action/sw6oidc/provider/test-connection',
        name: 'api.action.sw6oidc.provider.test-connection',
        defaults: ['_acl' => ['sw6oidc_provider:update']],
        methods: ['POST'],
    )]
    public function testConnection(Request $request, Context $context): JsonResponse
    {
        $providerId = $this->stringInput($request, 'providerId') ?? '';
        $hasClientSecret = trim($this->stringInput($request, 'clientSecret') ?? '') !== '';

        // client_secret is write-only over the API, so the form of an existing
        // provider sends nothing unless the admin typed a new one: fall back
        // to the stored secret.
        if (!$hasClientSecret && Uuid::isValid($providerId)) {
            $hasClientSecret = $this->loadProvider($providerId, $context)?->getUsableClientSecret() !== null;
        }

        $config = [
            'wellKnownConfigUrl' => $this->stringInput($request, 'wellKnownConfigUrl'),
            'authorizeEndpoint' => $this->stringInput($request, 'authorizeEndpoint'),
            'accessTokenEndpoint' => $this->stringInput($request, 'accessTokenEndpoint'),
            'userInfoEndpoint' => $this->stringInput($request, 'userInfoEndpoint'),
            'jwksEndpoint' => $this->stringInput($request, 'jwksEndpoint'),
            'endSessionEndpoint' => $this->stringInput($request, 'endSessionEndpoint'),
            'revocationEndpoint' => $this->stringInput($request, 'revocationEndpoint'),
            'issuer' => $this->stringInput($request, 'issuer'),
            'clientId' => $this->stringInput($request, 'clientId'),
            'hasClientSecret' => $hasClientSecret,
            'publicClient' => $request->request->getBoolean('publicClient'),
            'httpTimeout' => $this->timeoutInput($request),
        ];

        return new JsonResponse($this->connectionTestService->test($config));
    }

    #[Route(
        path: '/api/_action/sw6oidc/provider/{id}/test',
        name: 'api.action.sw6oidc.provider.test-start',
        defaults: ['_acl' => ['sw6oidc_provider:update']],
        methods: ['POST'],
    )]
    public function startLiveTest(string $id, Request $request, Context $context): JsonResponse
    {
        $provider = $this->loadProvider($id, $context);

        if (!$provider instanceof Sw6OidcProviderEntity) {
            return new JsonResponse(['error' => 'not_found', 'message' => 'Unknown provider.'], 404);
        }

        if ($provider->getAuthorizeEndpoint() === null || $provider->getAccessTokenEndpoint() === null) {
            return new JsonResponse([
                'error' => 'incomplete_configuration',
                'message' => 'This provider is missing its authorize or access token endpoint. Run discovery or fill them in manually before testing.',
            ], 400);
        }

        $redirectUri = $this->generateUrl('api.action.sw6oidc.provider.test-callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
        // The anonymous popup callback has no other way to know the admin's
        // UI locale, so the flow carries it.
        $locale = $this->translator->normalizeLocale((string) $request->request->get('locale', ''));
        $authorizeUrl = $this->requestBuilder->build($provider, LoginType::ProviderTest->value, '', $redirectUri, locale: $locale);

        return new JsonResponse(['authorizeUrl' => $authorizeUrl]);
    }

    /**
     * The anonymous return leg from the IdP — see class docblock for why this
     * can't require auth. Consumes the single-use cached flow state exactly
     * like the real admin callback (replay-proof), runs the safe live-login
     * test pipeline, persists the outcome, and renders a small static HTML
     * result page directly (no Administration SPA boot needed, since the
     * popup that navigates here is inherently anonymous at this point anyway).
     */
    #[Route(
        path: '/api/sw6oidc/provider/test-callback',
        name: 'api.action.sw6oidc.provider.test-callback',
        defaults: ['auth_required' => false],
        methods: ['GET'],
    )]
    public function testCallback(Request $request): Response
    {
        // Shopware's CoreSubscriber computes a fresh CSP nonce for every
        // request (regardless of controller) and, depending on the shop's
        // config/packages/csp.yaml, may attach a Content-Security-Policy
        // header to this response too — without the nonce, the inline
        // <script> below would silently fail to run entirely.
        $cspNonce = $request->attributes->get(PlatformRequest::ATTRIBUTE_CSP_NONCE);
        $cspNonce = \is_string($cspNonce) ? $cspNonce : null;

        $state = $request->query->get('state');

        try {
            $flow = $this->securityHelper->consumeAuthorizationFlow(\is_string($state) ? $state : null);
        } catch (InvalidStateException) {
            // No flow, so no stored admin locale: best effort from the browser.
            $locale = $this->translator->normalizeLocale($request->getPreferredLanguage());

            return $this->renderTestResultPage('fail', [
                ['id' => 'callback', 'status' => 'fail', 'detail' => 'Unknown, expired, or already-used test state.', 'messageKey' => 'callbackInvalidState'],
            ], [], $cspNonce, $locale);
        }

        if ($flow->loginType !== LoginType::ProviderTest->value) {
            $this->logger->warning('sw6oidc: provider test callback received a non-test authorization flow; refusing.', [
                'providerId' => $flow->providerId,
            ]);

            return $this->renderTestResultPage('fail', [
                [
                    'id' => 'callback',
                    'status' => 'fail',
                    'detail' => 'This callback only accepts test-mode authorization flows.',
                    'messageKey' => 'callbackNotTestFlow',
                ],
            ], [], $cspNonce, $this->translator->normalizeLocale($request->getPreferredLanguage()));
        }

        $locale = $this->translator->normalizeLocale($flow->locale ?? '');

        $context = Context::createDefaultContext();

        if ($request->query->get('error') !== null) {
            $this->logger->warning('sw6oidc: IdP returned an OAuth error on the provider test callback.', [
                'providerId' => $flow->providerId,
                'error' => $request->query->get('error'),
            ]);

            $this->persistTestStatus($flow->providerId, 'fail', $context);

            $description = $request->query->get('error_description') ?? $request->query->get('error');

            return $this->renderTestResultPage('fail', [
                [
                    'id' => 'authorization',
                    'status' => 'fail',
                    'detail' => (string) $description,
                    'messageKey' => 'authorizationError',
                    'messageParams' => ['error' => (string) $description],
                ],
            ], [], $cspNonce, $locale);
        }

        $code = $request->query->get('code');
        $provider = $this->loadProvider($flow->providerId, $context);

        if (!$provider instanceof Sw6OidcProviderEntity || $code === null || $code === '') {
            $this->persistTestStatus($flow->providerId, 'fail', $context);

            return $this->renderTestResultPage('fail', [
                [
                    'id' => 'callback',
                    'status' => 'fail',
                    'detail' => 'Missing authorization code or unknown provider.',
                    'messageKey' => 'callbackMissingCode',
                ],
            ], [], $cspNonce, $locale);
        }

        $redirectUri = $this->generateUrl('api.action.sw6oidc.provider.test-callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
        $result = $this->liveLoginTestService->run($provider, $code, $flow->codeVerifier, $redirectUri, $flow->nonce);

        $this->persistTestStatus($provider->getId(), $result['status'], $context, $result['claims']);

        return $this->renderTestResultPage($result['status'], $result['steps'], $result['claims'], $cspNonce, $locale);
    }

    /**
     * Deletes a provider although accounts are bound to it: the
     * Administration asked first, because those accounts lose SSO (their
     * bindings go with the provider). A plain DAL delete of such a provider is
     * refused by the write guard (R3-L43).
     */
    #[Route(
        path: '/api/_action/sw6oidc/provider/{id}/delete',
        name: 'api.action.sw6oidc.provider.delete',
        defaults: ['_acl' => ['sw6oidc_provider:delete']],
        methods: ['POST'],
    )]
    public function deleteWithBindings(string $id, Context $context): JsonResponse
    {
        if (!$this->loadProvider($id, $context) instanceof Sw6OidcProviderEntity) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }

        $context->addState(Sw6OidcProviderWriteGuardSubscriber::STATE_BINDING_LOSS_CONFIRMED);

        try {
            $this->providerRepository->delete([['id' => $id]], $context);
        } finally {
            $context->removeState(Sw6OidcProviderWriteGuardSubscriber::STATE_BINDING_LOSS_CONFIRMED);
        }

        return new JsonResponse(['status' => true]);
    }

    private function loadProvider(string $id, Context $context): ?Sw6OidcProviderEntity
    {
        $provider = Uuid::isValid($id) ? $this->providerRepository->search(new Criteria([$id]), $context)->first() : null;

        return $provider instanceof Sw6OidcProviderEntity ? $provider : null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function persistTestStatus(string $providerId, string $status, Context $context, array $claims = []): void
    {
        $payload = [
            'id' => $providerId,
            'lastTestStatus' => $status,
            'lastTestAt' => new \DateTimeImmutable(),
        ];

        // Only overwrite previously-persisted claims when this run actually
        // produced some — a re-test that fails before reaching the IdP at
        // all (or the early guard clauses above, which never call this with
        // any $claims) must not wipe out the claims a prior successful test
        // already gave the admin to work with in the attribute-mapping
        // picker.
        //
        // Only the claim *keys* are kept (M13): the attribute-mapping picker
        // needs nothing else, and the values are the tester's personal data,
        // readable by every provider viewer. The values are shown once, in
        // the result popup of the admin who ran the test.
        if ($claims !== []) {
            $payload['lastTestClaims'] = array_fill_keys(\array_slice(array_map(strval(...), array_keys($claims)), 0, self::MAX_STORED_CLAIM_KEYS), null);
        }

        $this->providerRepository->update([$payload], $context);
    }

    /**
     * A string request field, or null when absent. Any other JSON type is a
     * client error, not a TypeError deep inside the test (R3-L44).
     */
    private function stringInput(Request $request, string $key): ?string
    {
        $value = $request->request->all()[$key] ?? null;

        if ($value === null || \is_string($value)) {
            return $value;
        }

        throw new BadRequestHttpException(sprintf('"%s" must be a string.', $key));
    }

    /**
     * The test timeout in seconds, clamped to 1–30 (R3-L44): the endpoints
     * run inside the admin's request.
     */
    private function timeoutInput(Request $request): int
    {
        $value = $request->request->all()['httpTimeout'] ?? self::DEFAULT_TEST_TIMEOUT_SECONDS;

        if (!is_numeric($value)) {
            throw new BadRequestHttpException('"httpTimeout" must be a number.');
        }

        return max(1, min(self::MAX_TEST_TIMEOUT_SECONDS, (int) $value));
    }

    /**
     * @param array<int, array{id: string, status: string, detail: string, messageKey?: string, messageParams?: array<string, string|int>}> $steps
     * @param array<string, mixed> $claims
     */
    private function renderTestResultPage(string $status, array $steps, array $claims, ?string $cspNonce, string $locale): Response
    {
        // Same snippet keys, wording and pill layout as the provider detail
        // page's "Live login test results" card (sw6oidc-provider-detail).
        $t = fn (string $key, array $params = []): string => $this->translator->trans('sw6oidc.provider.detail.' . $key, $locale, $params);

        $stepsHtml = '';

        foreach ($steps as $step) {
            $stepLabelKey = 'liveTest.step.' . $step['id'];
            $stepLabel = $t($stepLabelKey);

            if ($stepLabel === 'sw6oidc.provider.detail.' . $stepLabelKey) {
                $stepLabel = $step['id'];
            }

            $message = isset($step['messageKey'])
                ? $t('testMessage.' . $step['messageKey'], $step['messageParams'] ?? [])
                : $step['detail'];

            $stepsHtml .= sprintf(
                '<li class="result-list__item"><strong>%s:</strong> <span>%s</span> %s</li>',
                $this->escapeForDisplay($stepLabel),
                $this->escapeForDisplay($message),
                $this->renderStatusPill($step['status'], $t),
            );
        }

        $claimsHtml = '';

        foreach ($claims as $key => $value) {
            $displayValue = \is_array($value) ? json_encode($value) : (string) $value;
            $claimsHtml .= sprintf(
                '<tr><td>%s</td><td>%s</td></tr>',
                $this->escapeForDisplay((string) $key),
                $this->escapeForDisplay((string) $displayValue),
            );
        }

        $claimsSection = $claimsHtml === ''
            ? sprintf('<p class="muted">%s</p>', $this->escapeForDisplay($t('liveTestPopup.noClaims')))
            : sprintf(
                '<table><thead><tr><th>%s</th><th>%s</th></tr></thead><tbody>%s</tbody></table>',
                $this->escapeForDisplay($t('liveTestPopup.columnClaim')),
                $this->escapeForDisplay($t('liveTestPopup.columnValue')),
                $claimsHtml,
            );

        $pageTitle = $this->escapeForDisplay($t('liveTestResultTitle'));
        $overallLabel = $this->escapeForDisplay($t('liveTestPopup.overallLabel'));
        $overallPill = $this->renderStatusPill($status, $t);
        $claimsTitle = $this->escapeForDisplay($t('liveTestPopup.claimsTitle'));
        $closeLabel = $this->escapeForDisplay($t('liveTestPopup.closeButton'));
        $htmlLang = htmlspecialchars($locale, \ENT_QUOTES);

        // JSON_HEX_* (not htmlspecialchars) is the correct escaping here: this
        // is embedded directly as a JS object literal inside <script>, whose
        // content is raw text to the HTML parser — HTML entities would not be
        // decoded and would break the literal instead of protecting it.
        //
        // `claims` rides along so the provider detail page can offer them as
        // attribute-mapping suggestions — no new exposure, since the same
        // claim values are already rendered in plain text on this same popup
        // page (see the "Claims received" table above) to the same
        // authenticated admin who triggered this test.
        $payloadJson = json_encode(
            ['type' => 'sw6oidc-test-result', 'status' => $status, 'steps' => $steps, 'claims' => $claims],
            \JSON_HEX_TAG | \JSON_HEX_AMP | \JSON_HEX_APOS | \JSON_HEX_QUOT,
        ) ?: '{}';

        // Required for the inline <script>/<style> below to run at all: this
        // route's _routeScope is 'api', whose CSP template Shopware applies
        // is `script-src 'none'` outright (no %nonce% token to substitute at
        // all, confirmed by the browser's own CSP violation report) — a
        // nonce attribute alone cannot satisfy a bare 'none' directive.
        // Instead, this response sets its OWN Content-Security-Policy header
        // scoped to exactly this nonce (see the end of this method);
        // CoreSubscriber only ever applies its header
        // `if (!$response->headers->has('Content-Security-Policy'))`, so a
        // header already present here wins. The "Close window" button
        // deliberately has no onclick="" attribute: a CSP nonce only ever
        // authorizes <script> elements, never inline event-handler
        // attributes, so the listener is attached from inside this nonced
        // script instead.
        $nonceAttr = $cspNonce !== null ? sprintf(' nonce="%s"', htmlspecialchars($cspNonce, \ENT_QUOTES)) : '';
        $scriptTag = '<script' . $nonceAttr . '>';
        $styleTag = '<style' . $nonceAttr . '>';

        // Colours, radii and sizes are the Meteor design tokens the
        // Administration's sw-card / sw-label (size medium, appearance pill)
        // resolve to, hard-coded because this page loads no admin CSS.
        $html = <<<HTML
            <!doctype html>
            <html lang="{$htmlLang}">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>{$pageTitle}</title>
                {$styleTag}
                    * { box-sizing: border-box; }
                    body {
                        margin: 0; padding: 24px; background: #f9fafb; color: #1e1e24;
                        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        font-size: 14px; line-height: 1.5;
                    }
                    .card { background: #fff; border: 1px solid #e0e0e5; border-radius: 8px; margin-bottom: 24px; }
                    .card__header {
                        display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 16px;
                        padding: 20px 24px; border-bottom: 1px solid #e0e0e5;
                    }
                    .card__title { margin: 0; font-size: 18px; font-weight: 600; }
                    .card__content { padding: 24px; }
                    .overall { display: inline-flex; align-items: center; gap: 8px; }
                    .result-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 12px; }
                    .result-list__item { display: flex; align-items: center; flex-wrap: wrap; gap: 0.3em 0.4em; }
                    .pill {
                        display: inline-flex; align-items: center; height: 24px; padding: 4px 12px;
                        border: 1px solid; border-radius: 50px; font-size: 12px; line-height: 14px; white-space: nowrap;
                    }
                    .pill--success { background: #e1ffe0; border-color: #36d046; color: #1e1e24; }
                    .pill--danger { background: #fff2f0; border-color: #e2262a; color: #e2262a; }
                    .pill--warning { background: #fff3e3; border-color: #fbaf18; color: #1e1e24; }
                    .pill--neutral { background: #f2f3f8; border-color: #cdced4; color: #696a6e; }
                    table { border-collapse: collapse; width: 100%; }
                    th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid #e0e0e5; word-break: break-word; }
                    th { font-weight: 600; background: #f9fafb; }
                    tbody tr:last-child td { border-bottom: 0; }
                    .muted { margin: 0; color: #696a6e; }
                    .actions { display: flex; justify-content: flex-end; }
                    .button {
                        height: 36px; padding: 0 16px; border: 1px solid #cdced4; border-radius: 4px; background: #fff;
                        color: #1e1e24; font: inherit; font-weight: 600; cursor: pointer;
                    }
                    .button:hover { background: #f2f3f8; }
                </style>
            </head>
            <body>
                <section class="card">
                    <header class="card__header">
                        <h1 class="card__title">{$pageTitle}</h1>
                        <span class="overall"><strong>{$overallLabel}:</strong> {$overallPill}</span>
                    </header>
                    <div class="card__content">
                        <ul class="result-list">{$stepsHtml}</ul>
                    </div>
                </section>
                <section class="card">
                    <header class="card__header"><h2 class="card__title">{$claimsTitle}</h2></header>
                    <div class="card__content">{$claimsSection}</div>
                </section>
                <div class="actions">
                    <button id="sw6oidc-close-button" class="button" type="button">{$closeLabel}</button>
                </div>
                {$scriptTag}
                    (function () {
                        var payload = {$payloadJson};
                        if (window.opener && !window.opener.closed) {
                            try {
                                window.opener.postMessage(payload, window.location.origin);
                            } catch (e) { /* opener on a different origin or already gone — ignore */ }
                        }
                        document.getElementById('sw6oidc-close-button').addEventListener('click', function () {
                            window.close();
                        });
                    })();
                </script>
            </body>
            </html>
            HTML;

        $response = new Response($html, 200, ['Content-Type' => 'text/html; charset=utf-8']);

        // Override the api-scope's `script-src 'none'` default with a policy
        // scoped tightly to just this self-contained page: nonce'd inline
        // script/style only, nothing else allowed at all (no external
        // resources, forms, or navigation are used here). Skipped when no
        // nonce is available (should not happen in practice — CoreSubscriber
        // always sets one — but a missing nonce means we cannot construct a
        // safe policy, so fall back to leaving Shopware's own default header
        // in place rather than emitting an unenforceable or overly-loose one).
        if ($cspNonce !== null) {
            $response->headers->set('Content-Security-Policy', sprintf(
                "default-src 'none'; script-src 'nonce-%1\$s'; style-src 'nonce-%1\$s'; base-uri 'none'; form-action 'none'",
                $cspNonce,
            ));
        }

        return $response;
    }

    /**
     * Mirrors sw6oidc-provider-detail's testStatusVariant() + testStatus.* snippets.
     *
     * @param callable(string): string $t
     */
    private function renderStatusPill(string $status, callable $t): string
    {
        $variant = ['pass' => 'success', 'warning' => 'warning', 'skipped' => 'neutral'][$status] ?? 'danger';
        $knownStatus = \in_array($status, ['pass', 'fail', 'warning', 'skipped'], true) ? $status : 'fail';

        return sprintf(
            '<span class="pill pill--%s">%s</span>',
            $variant,
            $this->escapeForDisplay($t('testStatus.' . $knownStatus)),
        );
    }

    /**
     * HTML-escapes a value for display, then neutralizes "@" so hosting-layer
     * email obfuscation (e.g. Cloudflare's "Email Address Obfuscation" /
     * Scrape Shield) never rewrites a claim value into its masked
     * "[email protected]" placeholder + decoder-script form — the whole point
     * of this page is to show the admin the real, exact value the IdP
     * returned. Rendering "@" as a numeric character reference displays
     * identically in the browser but no longer matches a plain-text scanner
     * looking for a literal "user@domain" pattern in the response body.
     */
    private function escapeForDisplay(string $value): string
    {
        return str_replace('@', '&#64;', htmlspecialchars($value, \ENT_QUOTES));
    }
}
