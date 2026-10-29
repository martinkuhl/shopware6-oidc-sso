import template from './sw-profile-index-general.html.twig';

/**
 * Shows the logged-in admin their own "OIDC Provider" binding on
 * "Mein Profil" > General. Read-only: unlinking stays an action on the user
 * detail page, for admins holding users_and_permissions.editor.
 *
 * Rendered as its own card right after the profile information card
 * (sibling of sw_profile_index_general_information, R3-F8): blocks inside
 * that card, such as sw_profile_index_general_image, sit in its field grid,
 * so a card placed there would land in a grid cell.
 */
Shopware.Component.override('sw-profile-index-general', {
    template,
});
