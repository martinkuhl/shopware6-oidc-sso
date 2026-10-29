import './page/sw6oidc-sessions-list';
import { registerModuleWhenReady } from '../../service/defer-module-register';

/**
 * Session activity log (sw6oidc_session_activity): every OIDC/Passkey login
 * with its logout time and reason, plus a "Force logout" row action. Role
 * privileges: acl/index.js (viewer, force_logout).
 *
 * Registered via registerModuleWhenReady() rather than a bare
 * Shopware.Module.register() call - see that function's own comment for why.
 */
registerModuleWhenReady('sw6oidc-sessions', {
    type: 'plugin',
    name: 'sw6oidc-sessions',
    title: 'sw6oidc.sessions.moduleTitle',
    description: 'sw6oidc.sessions.moduleTitle',
    color: '#9AA8B5',
    icon: 'regular-clock',
    entity: 'sw6oidc_session_activity',

    routes: {
        index: {
            component: 'sw6oidc-sessions-list',
            path: 'index',
            meta: {
                privilege: 'sw6oidc_session_activity.viewer',
            },
        },
    },

    settingsItem: [{
        group: 'plugins',
        to: 'sw6oidc.sessions.index',
        icon: 'regular-clock',
        label: 'sw6oidc.sessions.moduleTitle',
        privilege: 'sw6oidc_session_activity.viewer',
    }],
});
