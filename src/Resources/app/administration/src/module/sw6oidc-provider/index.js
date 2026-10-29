import './page/sw6oidc-provider-list';
import './page/sw6oidc-provider-detail';
import { registerModuleWhenReady } from '../../service/defer-module-register';

/**
 * Administration module for managing OIDC providers (+ nested attribute/role
 * mappings). The role privileges (sw6oidc_provider.viewer/editor/creator/
 * deleter) are mapped in acl/index.js.
 *
 * Registered via registerModuleWhenReady() rather than a bare
 * Shopware.Module.register() call - see that function's own comment for why.
 */
registerModuleWhenReady('sw6oidc-provider', {
    type: 'plugin',
    name: 'sw6oidc-provider',
    title: 'sw6oidc.provider.moduleTitle',
    description: 'sw6oidc.provider.moduleTitle',
    color: '#9AA8B5',
    icon: 'regular-key',
    entity: 'sw6oidc_provider',

    routes: {
        index: {
            component: 'sw6oidc-provider-list',
            path: 'index',
            meta: {
                privilege: 'sw6oidc_provider.viewer',
            },
        },
        detail: {
            component: 'sw6oidc-provider-detail',
            path: 'detail/:id',
            meta: {
                privilege: 'sw6oidc_provider.viewer',
            },
        },
        create: {
            component: 'sw6oidc-provider-detail',
            path: 'create',
            meta: {
                privilege: 'sw6oidc_provider.creator',
            },
        },
    },

    settingsItem: [{
        group: 'plugins',
        to: 'sw6oidc.provider.index',
        icon: 'regular-key',
        label: 'sw6oidc.provider.moduleTitle',
        privilege: 'sw6oidc_provider.viewer',
    }],
});
