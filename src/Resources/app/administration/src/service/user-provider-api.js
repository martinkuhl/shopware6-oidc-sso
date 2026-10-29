/**
 * Thin client for OidcUserProviderAdminController - the "OIDC Provider"
 * binding shown on the admin user and customer pages, through the plugin's
 * ApiService (API base path and token refresh like core, F-H4).
 */
function api() {
    return Shopware.Service('sw6oidcApiService');
}

/**
 * @returns {Promise<Object<string, {providerId: string, providerName: ?string, createdAt: ?string}>>}
 *          keyed by user/customer id; unbound ids are absent
 */
export async function fetchUserProviderBindings(userType, userIds) {
    if (!userIds.length) {
        return {};
    }

    const { bindings } = await api().post('_action/sw6oidc/user-provider/info', {
        userType,
        userIds: userIds.join(','),
    });

    return bindings ?? {};
}

export async function unlinkUserProvider(userType, userId) {
    await api().post('_action/sw6oidc/user-provider/unlink', { userType, userId });
}
