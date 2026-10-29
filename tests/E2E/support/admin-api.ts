import { APIRequestContext, request } from '@playwright/test';
import { SHOP_ADMIN, SHOP_URL } from './fixtures';

/**
 * A logged-in Admin API client (password grant with the dockware admin).
 * `user-verified` (core adds `write`) is what core's `/api/user` and
 * `/api/acl-role` routes require, see saveUserEntity().
 */
export async function adminApi(): Promise<APIRequestContext> {
    const anonymous = await request.newContext({ baseURL: SHOP_URL });
    const response = await anonymous.post('/api/oauth/token', {
        data: { grant_type: 'password', client_id: 'administration', scope: 'user-verified', ...SHOP_ADMIN },
    });

    if (!response.ok()) {
        throw new Error(`Admin API login failed: HTTP ${response.status()} ${await response.text()}`);
    }

    const { access_token: token } = await response.json();
    await anonymous.dispose();

    return request.newContext({
        baseURL: SHOP_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
}

/**
 * Upsert via the sync API, so re-running the setup is idempotent.
 */
export async function upsert(api: APIRequestContext, entity: string, payload: Record<string, unknown>[]): Promise<void> {
    const response = await api.post('/api/_action/sync', {
        data: [{ action: 'upsert', entity, payload }],
        headers: { 'single-operation': '1' },
    });

    if (!response.ok()) {
        throw new Error(`Upserting ${entity} failed: HTTP ${response.status()} ${await response.text()}`);
    }
}

/**
 * Upsert of a user or ACL role. Since Shopware 6.7.15 both are write
 * protected for the generic CRUD and sync APIs; only core's own routes
 * (POST /api/user, POST /api/acl-role, upsert by id) may write them.
 */
export async function saveUserEntity(api: APIRequestContext, route: 'user' | 'acl-role', payload: Record<string, unknown>): Promise<void> {
    const response = await api.post(`/api/${route}`, { data: payload });

    if (!response.ok()) {
        throw new Error(`Saving ${route} failed: HTTP ${response.status()} ${await response.text()}`);
    }
}
