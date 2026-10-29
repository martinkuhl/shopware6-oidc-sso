import Plugin from 'src/plugin-system/plugin.class';
import {
    preparePublicKeyCreationOptions,
    serializeAttestationCredential,
} from './webauthn-codec';

/**
 * Self-service Passkey registration under My Account > Passkeys, against
 * PasskeyController's registration-options/registration-verify (URLs from
 * the template, F-H3). The nickname comes from the form's own input and
 * errors are shown inline — no window.prompt()/alert(). Reloads on success
 * so the server-rendered list shows the new credential.
 */
export default class Sw6OidcPasskeyRegistrationPlugin extends Plugin {
    init() {
        this.errorElement = document.getElementById(this.el.dataset.sw6oidcErrorTarget || '');
        this.nicknameInput = document.getElementById(this.el.dataset.sw6oidcNicknameInput || '');
        this.el.addEventListener('click', this.register.bind(this));
    }

    async register() {
        if (!window.PublicKeyCredential) {
            this.showError(this.el.dataset.sw6oidcNoSupportText);
            return;
        }

        this.el.disabled = true;
        this.hideError();

        try {
            const optionsResponse = await this.post(this.el.dataset.sw6oidcOptionsUrl);

            if (optionsResponse.status === 403) {
                // Adding a passkey needs a recent login: re-authenticate first.
                const { reauthUrl } = await optionsResponse.json();

                if (typeof reauthUrl === 'string' && reauthUrl.startsWith('/') && !reauthUrl.startsWith('//')) {
                    window.location.assign(reauthUrl);
                    return;
                }
            }

            if (!optionsResponse.ok) {
                throw new Error(`Registration options request failed with status ${optionsResponse.status}`);
            }

            const { sessionId, options } = await optionsResponse.json();

            const credential = await navigator.credentials.create({
                publicKey: preparePublicKeyCreationOptions(options),
            });

            const nickname = (this.nicknameInput?.value || '').trim();
            const verifyResponse = await this.post(this.el.dataset.sw6oidcVerifyUrl, {
                sessionId,
                credential: JSON.stringify(serializeAttestationCredential(credential)),
                ...(nickname ? { nickname } : {}),
            });

            if (!verifyResponse.ok) {
                throw new Error(`Registration failed with status ${verifyResponse.status}`);
            }

            const result = await verifyResponse.json();

            if (!result.status) {
                throw new Error('Registration was refused.');
            }

            window.location.reload();
        } catch (error) {
            if (error?.name !== 'NotAllowedError') {
                // eslint-disable-next-line no-console
                console.error('sw6oidc: passkey registration failed', error);
                this.showError(this.el.dataset.sw6oidcErrorText);
            }
        } finally {
            this.el.disabled = false;
        }
    }

    post(url, fields = {}) {
        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: new URLSearchParams(fields),
        });
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
