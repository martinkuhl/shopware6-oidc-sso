import Plugin from 'src/plugin-system/plugin.class';
import {
    preparePublicKeyRequestOptions,
    serializeAssertionCredential,
} from './webauthn-codec';

/**
 * Usernameless/discoverable Passkey login on the Storefront login page,
 * against PasskeyController's login-options/login-verify. The URLs come from
 * the template (`{{ path() }}`), so sales channels with a path prefix work
 * (F-H3). On success, reloads so the new context token takes effect.
 */
export default class Sw6OidcPasskeyLoginPlugin extends Plugin {
    init() {
        this.errorElement = document.getElementById(this.el.dataset.sw6oidcErrorTarget || '');
        this.el.addEventListener('click', this.login.bind(this));
    }

    async login() {
        if (!window.PublicKeyCredential) {
            this.showError(this.el.dataset.sw6oidcNoSupportText);
            return;
        }

        this.el.disabled = true;
        this.hideError();

        try {
            const { sessionId, options } = await this.postJson(this.el.dataset.sw6oidcOptionsUrl);

            const assertion = await navigator.credentials.get({
                publicKey: preparePublicKeyRequestOptions(options),
            });

            const result = await this.postJson(this.el.dataset.sw6oidcVerifyUrl, {
                sessionId,
                credential: JSON.stringify(serializeAssertionCredential(assertion)),
            });

            if (result.status) {
                window.location.reload();

                return;
            }

            this.showError(this.el.dataset.sw6oidcErrorText);
        } catch (error) {
            // A cancelled browser dialog is not an error worth showing.
            if (error?.name !== 'NotAllowedError') {
                // eslint-disable-next-line no-console
                console.error('sw6oidc: passkey login failed', error);
                this.showError(this.el.dataset.sw6oidcErrorText);
            }
        } finally {
            this.el.disabled = false;
        }
    }

    /**
     * POSTs form fields and returns the JSON body; checks the status before
     * parsing (F-M11).
     */
    async postJson(url, fields = {}) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: new URLSearchParams(fields),
        });

        if (!response.ok) {
            throw new Error(`sw6oidc: ${url} answered HTTP ${response.status}`);
        }

        return response.json();
    }

    showError(message) {
        if (!this.errorElement || !message) {
            return;
        }

        this.errorElement.textContent = message;
        this.errorElement.hidden = false;
    }

    hideError() {
        if (this.errorElement) {
            this.errorElement.hidden = true;
        }
    }
}
