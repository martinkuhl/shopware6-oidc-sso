import Plugin from 'src/plugin-system/plugin.class';

/**
 * Asks before deleting a passkey, in a native <dialog> rendered next to the
 * form instead of window.confirm(). Without dialog support the form submits
 * directly (the delete is easy to redo by registering again).
 *
 * Only the form that opened the dialog submits on confirm (R3-F3): every
 * row has its own dialog, and a close this form didn't start is ignored.
 */
export default class Sw6OidcPasskeyDeleteConfirmPlugin extends Plugin {
    init() {
        this.dialog = document.getElementById(this.el.dataset.sw6oidcConfirmDialog || '');
        this.confirmed = false;
        this.awaitingConfirmation = false;
        this.el.addEventListener('submit', this.onSubmit.bind(this));

        if (this.dialog && typeof this.dialog.showModal === 'function') {
            this.dialog.addEventListener('close', this.onDialogClose.bind(this));
        }
    }

    onSubmit(event) {
        if (this.confirmed || !this.dialog || typeof this.dialog.showModal !== 'function') {
            return;
        }

        event.preventDefault();
        this.dialog.returnValue = '';
        this.awaitingConfirmation = true;
        this.dialog.showModal();
    }

    onDialogClose() {
        if (!this.awaitingConfirmation) {
            return;
        }

        this.awaitingConfirmation = false;

        if (this.dialog.returnValue === 'confirm') {
            this.confirmed = true;
            this.el.requestSubmit ? this.el.requestSubmit() : this.el.submit();
        }
    }
}
