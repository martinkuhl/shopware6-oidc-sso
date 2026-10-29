/**
 * The plugin's Admin API client: every call goes through Shopware's own
 * HTTP client, so the API base path (sub-folder installs), the language
 * header and the transparent access-token refresh all work like in core.
 * Paths are relative to the API base, e.g. 'sw6oidc/admin/step-up/methods'.
 *
 * `anonymous: true` omits the Authorization header — for the pre-auth login
 * screen, where there is no token yet — and keeps the request away from
 * core's token-refresh interceptor: a 401 on an anonymous call would
 * otherwise wait for a refresh that never comes, and never settle (R3-F5).
 */
const { ApiService } = Shopware.Classes;

export default class Sw6oidcApiService extends ApiService {
    constructor(httpClient, loginService) {
        super(httpClient, loginService, 'sw6oidc', 'application/json');
        this.name = 'sw6oidcApiService';
    }

    get(path, { anonymous = false, params = {} } = {}) {
        return this.httpClient
            .get(path, { params, ...this.sw6oidcConfig(anonymous) })
            .then(ApiService.handleResponse);
    }

    post(path, data = {}, { anonymous = false } = {}) {
        return this.httpClient
            .post(path, data, this.sw6oidcConfig(anonymous))
            .then(ApiService.handleResponse);
    }

    sw6oidcConfig(anonymous) {
        const config = { headers: this.sw6oidcHeaders(anonymous) };

        if (anonymous) {
            // core's refreshTokenInterceptor never refreshes a request marked as already retried
            config._tokenRefreshRetry = true;
        }

        return config;
    }

    sw6oidcHeaders(anonymous) {
        const headers = this.getBasicHeaders();

        if (anonymous) {
            delete headers.Authorization;
        }

        return headers;
    }

    /**
     * Absolute URL of an API route, for full-page navigations (SSO redirects).
     */
    static absoluteUrl(path) {
        const base = (Shopware.Context.api.apiPath ?? '/api').replace(/\/+$/, '');

        return `${base}/${path.replace(/^\/+/, '')}`;
    }

    /**
     * The fixed error code of a failed request (see PublicError on the server).
     */
    static errorCode(error) {
        return error?.response?.data?.error ?? null;
    }
}

Shopware.Service().register('sw6oidcApiService', (container) => {
    const initContainer = Shopware.Application.getContainer('init');

    return new Sw6oidcApiService(initContainer.httpClient, container.loginService);
});
