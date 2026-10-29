// Loaded on demand: only pages with a matching element fetch the plugin code.
const PluginManager = window.PluginManager;
PluginManager.register('Sw6OidcPasskeyLogin', () => import('./passkey/passkey-login.plugin'), '[data-sw6oidc-passkey-login]');
PluginManager.register('Sw6OidcPasskeyRegistration', () => import('./passkey/passkey-registration.plugin'), '[data-sw6oidc-passkey-register]');
PluginManager.register('Sw6OidcPasskeyDeleteConfirm', () => import('./passkey/passkey-delete-confirm.plugin'), '[data-sw6oidc-passkey-delete-form]');
