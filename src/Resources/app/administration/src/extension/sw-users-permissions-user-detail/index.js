import template from './sw-users-permissions-user-detail.html.twig';

/**
 * Read-only "OIDC Provider" row (+ "Unlink IdP") in the user detail's
 * basic information card.
 */
Shopware.Component.override('sw-users-permissions-user-detail', {
    template,
});
