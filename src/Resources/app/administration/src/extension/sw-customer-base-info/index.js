import template from './sw-customer-base-info.html.twig';

/**
 * "OIDC Provider" row (+ "Unlink IdP") in the customer detail's base info
 * metadata, next to "Last login".
 */
Shopware.Component.override('sw-customer-base-info', {
    template,
});
