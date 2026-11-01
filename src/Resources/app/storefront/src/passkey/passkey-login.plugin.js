import Plugin from 'src/plugin-system/plugin.class';
import {
    isConditionalMediationAvailable,
    preparePublicKeyRequestOptions,
    serializeAssertionCredential,
} from '../../../shared/webauthn-codec';

/**
 * Usernameless/discoverable Passkey login on the Storefront login page,
 * against PasskeyController's login-options/login-verify. The URLs come from
 * the template (`{{ path() }}`), so sales channels with a path prefix work
 * (F-H3). On success, reloads so the new context token takes effect.
 *
 * Besides the button, the browser offers the passkeys in the email field's
 * autofill (conditional mediation; core marks the field `username webauthn`).
 * That request starts on the field's first focus, not on page load: every
 * request consumes the `options` rate-limit budget and creates a ceremony.
 * Only one WebAuthn request may be pending, so the button aborts it first.
 */
export default class Sw6OidcPasskeyLoginPlugin extends Plugin {
    init() {
        this.errorElement = document.getElementById(this.el.dataset.sw6oidcErrorTarget || '');
        this.conditionalAbort = null;
        this.conditionalArmed = false;
        this.el.addEventListener('click', this.login.bind(this));
        this.armConditionalLogin();
    }

    async armConditionalLogin() {
        const field = document.getElementById('loginMail');

        if (this.conditionalArmed || !field) {
            return;
        }

        this.conditionalArmed = true;

        if (!(await isConditionalMediationAvailable())) {
            return;
        }

        field.addEventListener('focus', () => {
            this.conditionalArmed = false;
            this.startConditionalLogin();
        }, { once: true });
    }

    async startConditionalLogin() {
        const abort = new AbortController();
        this.conditionalAbort = abort;

        try {
            await this.authenticate({ mediation: 'conditional', signal: abort.signal });
        } catch (error) {
            if (abort.signal.aborted) {
                return;
            }

            this.reportFailure(error);
        } finally {
            if (this.conditionalAbort === abort) {
                this.conditionalAbort = null;
            }
        }

        // Failed (e.g. the ceremony expired while the field sat idle): offer it again on the next focus.
        if (!abort.signal.aborted) {
            this.armConditionalLogin();
        }
    }

    async login() {
        if (!window.PublicKeyCredential) {
            this.showError(this.el.dataset.sw6oidcNoSupportText);
            return;
        }

        this.conditionalAbort?.abort();
        this.el.disabled = true;
        this.hideError();

        try {
            await this.authenticate({});
        } catch (error) {
            this.reportFailure(error);
        } finally {
            this.el.disabled = false;
            this.armConditionalLogin();
        }
    }

    /**
     * One ceremony: options, browser assertion, verify. Reloads on success,
     * throws on failure.
     */
    async authenticate(request) {
        const { sessionId, options } = await this.postJson(this.el.dataset.sw6oidcOptionsUrl);

        const assertion = await navigator.credentials.get({
            ...request,
            publicKey: preparePublicKeyRequestOptions(options),
        });

        const result = await this.postJson(this.el.dataset.sw6oidcVerifyUrl, {
            sessionId,
            credential: JSON.stringify(serializeAssertionCredential(assertion)),
        });

        if (!result.status) {
            throw new Error('sw6oidc: passkey login was not accepted');
        }

        window.location.reload();
    }

    reportFailure(error) {
        // A cancelled browser dialog is not an error worth showing.
        if (error?.name === 'NotAllowedError' || error?.name === 'AbortError') {
            return;
        }

        // eslint-disable-next-line no-console
        console.error('sw6oidc: passkey login failed', error);
        this.showError(this.el.dataset.sw6oidcErrorText);
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
