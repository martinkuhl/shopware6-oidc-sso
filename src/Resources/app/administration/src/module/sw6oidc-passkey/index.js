import './page/sw6oidc-passkey-list';
import { registerModuleWhenReady } from '../../service/defer-module-register';

/**
 * Lockout-recovery grid: lists every registered Passkey credential (admin +
 * customer) with a delete action. The enable toggles / RP name+id override
 * themselves need no custom UI at all — they're plain config.xml fields, so
 * Shopware already renders a config form for them under this plugin's own
 * entry in Settings > System > Plugins.
 *
 * Registered via registerModuleWhenReady() rather than a bare
 * Shopware.Module.register() call - see that function's own comment for why.
 */
registerModuleWhenReady('sw6oidc-passkey', {
    type: 'plugin',
    name: 'sw6oidc-passkey',
    title: 'sw6oidc.passkeySettings.moduleTitle',
    description: 'sw6oidc.passkeySettings.moduleTitle',
    color: '#9AA8B5',
    icon: 'regular-key',
    entity: 'sw6oidc_passkey_credential',

    routes: {
        index: {
            component: 'sw6oidc-passkey-list',
            path: 'index',
            meta: {
                privilege: 'sw6oidc_passkey_credential.viewer',
            },
        },
    },

    settingsItem: [{
        group: 'plugins',
        to: 'sw6oidc.passkey.index',
        icon: 'regular-key',
        label: 'sw6oidc.passkeySettings.moduleTitle',
        privilege: 'sw6oidc_passkey_credential.viewer',
    }],
});
