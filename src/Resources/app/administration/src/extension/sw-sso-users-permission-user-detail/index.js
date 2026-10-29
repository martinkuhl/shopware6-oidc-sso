import template from './sw-sso-users-permission-user-detail.html.twig';

/**
 * The OIDC provider row (with "Unlink IdP") on the user detail page core
 * uses when its native SSO mode is active.
 */
Shopware.Component.override('sw-sso-users-permission-user-detail', {
    template,
});
