import { whenReady } from '../service/defer-module-register';

/**
 * Role privileges for the plugin's modules (F-H5, F-N7): without these
 * mappings the entities' privileges can't be granted to a normal role, so
 * only superadmins could use the modules. Owner names in the passkey and
 * session lists need user/customer read access.
 *
 * The bundle runs before core registers the `privileges` service (it is
 * force-loaded on the login screen, see views/administration/index.html.twig),
 * so the registration waits for it, like registerModuleWhenReady (R3-F2).
 *
 * Changing a provider's endpoints, issuer, scope, superadmin mapping and the
 * other trust-relevant settings needs a superadmin, whatever role is granted
 * here (R3-H4, ProviderTrustGuardSubscriber).
 */
function registerPrivileges(privileges) {
    privileges.addPrivilegeMappingEntry({
        category: 'permissions',
        parent: 'settings',
        key: 'sw6oidc_provider',
        roles: {
            viewer: {
                privileges: [
                    'sw6oidc_provider:read',
                    'sw6oidc_attribute_mapping:read',
                    'sw6oidc_role_mapping:read',
                    'sw6oidc_access_control_rule:read',
                    'acl_role:read',
                    'customer_group:read',
                ],
                dependencies: [],
            },
            editor: {
                // Live test, discovery, connection test and lockout
                // confirmation are checked against sw6oidc_provider:update.
                privileges: [
                    'sw6oidc_provider:update',
                    'sw6oidc_attribute_mapping:create',
                    'sw6oidc_attribute_mapping:update',
                    'sw6oidc_attribute_mapping:delete',
                    'sw6oidc_role_mapping:create',
                    'sw6oidc_role_mapping:update',
                    'sw6oidc_role_mapping:delete',
                    'sw6oidc_access_control_rule:create',
                    'sw6oidc_access_control_rule:update',
                    'sw6oidc_access_control_rule:delete',
                ],
                dependencies: ['sw6oidc_provider.viewer'],
            },
            creator: {
                privileges: ['sw6oidc_provider:create'],
                dependencies: ['sw6oidc_provider.viewer', 'sw6oidc_provider.editor'],
            },
            deleter: {
                privileges: [
                    'sw6oidc_provider:delete',
                    'sw6oidc_attribute_mapping:delete',
                    'sw6oidc_role_mapping:delete',
                    'sw6oidc_access_control_rule:delete',
                ],
                dependencies: ['sw6oidc_provider.viewer'],
            },
        },
    });

    privileges.addPrivilegeMappingEntry({
        category: 'permissions',
        parent: 'settings',
        key: 'sw6oidc_passkey_credential',
        roles: {
            viewer: {
                privileges: ['sw6oidc_passkey_credential:read', 'user:read', 'customer:read'],
                dependencies: [],
            },
            deleter: {
                privileges: ['sw6oidc_passkey_credential:delete'],
                dependencies: ['sw6oidc_passkey_credential.viewer'],
            },
        },
    });

    privileges.addPrivilegeMappingEntry({
        category: 'permissions',
        parent: 'settings',
        key: 'sw6oidc_session_activity',
        roles: {
            viewer: {
                privileges: ['sw6oidc_session_activity:read', 'sw6oidc_provider:read', 'user:read', 'customer:read'],
                dependencies: [],
            },
        },
    });

    // The permissions grid only renders viewer/editor/creator/deleter; a
    // custom role belongs to the additional permissions (R3-F2).
    privileges.addPrivilegeMappingEntry({
        category: 'additional_permissions',
        parent: null,
        key: 'sw6oidc_session_activity',
        roles: {
            // Ends a customer's session, or all sessions of an admin.
            force_logout: {
                privileges: ['sw6oidc_session_activity:read', 'sw6oidc_session_activity:force_logout', 'user:read', 'customer:read'],
                dependencies: [],
            },
        },
    });
}

// No time limit: giving up on a slow connection dropped the privileges from the role editor (R6-L2).
whenReady(
    'the role privileges',
    () => Shopware.Service('privileges'),
    () => registerPrivileges(Shopware.Service('privileges')),
);
