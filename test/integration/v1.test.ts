import { describe, expect, test } from 'bun:test';

import type {
    AuthenticationService,
    OAuthCodeResult,
    OAuthService,
    SettingsService,
    V1Dependencies,
} from '../../src/contracts';
import { permissiveRouteSecurity } from '../../src/routes/routeSecurity';
import { createV1Router, UNAUTHORIZED_ERROR } from '../../src/routes/v1';

function createDependencies(): V1Dependencies & { saved: Map<string, string>; deleted: string[] } {
    const saved = new Map<string, string>();
    const deleted: string[] = [];
    const auth: AuthenticationService = {
        async authenticate(rawAuthorization) {
            return rawAuthorization === 'raw-client-token'
                ? { userId: 'discord-user', tokenHash: 'a'.repeat(64) }
                : null;
        },
        async authenticateReadOnly(rawAuthorization) {
            return rawAuthorization === 'raw-client-token'
                ? { userId: 'discord-user', tokenHash: 'a'.repeat(64) }
                : null;
        },
        async createSession() {
            return '0123456789abcdef0123456789abcdef';
        },
        async revokeAllSessions(userId) {
            deleted.push(`sessions:${userId}`);
        },
    };
    const settings: SettingsService = {
        async save(userId, value) {
            saved.set(userId, value);
        },
        async load(userId) {
            return saved.get(userId) ?? null;
        },
        async deleteForUser(userId) {
            deleted.push(`settings:${userId}`);
            saved.delete(userId);
        },
    };
    const oauth: OAuthService = {
        authorizationUrl: () => 'https://discord.com/oauth2/authorize',
        async userIdForCode(code): Promise<OAuthCodeResult> {
            return code === 'valid-code'
                ? { kind: 'success', userId: 'discord-user' }
                : { kind: 'invalid_code' };
        },
    };

    return {
        clientId: 'client-id',
        auth,
        settings,
        oauth,
        security: permissiveRouteSecurity,
        saved,
        deleted,
    };
}

describe('v1 client contract', () => {
    test('keeps raw authorization, settings payloads, and delete response compatible', async () => {
        const dependencies = createDependencies();
        const app = createV1Router(dependencies);

        const unauthorized = await app.request('/save', { method: 'POST' });
        expect(unauthorized.status).toBe(401);
        expect(await unauthorized.json()).toEqual({ error: UNAUTHORIZED_ERROR });

        const save = await app.request('/save', {
            method: 'POST',
            headers: { authorization: 'raw-client-token', 'content-type': 'application/json' },
            body: JSON.stringify({ settings: 'opaque-base64-payload' }),
        });
        expect(save.status).toBe(200);
        expect(await save.json()).toEqual({ success: true });

        const load = await app.request('/load', { headers: { authorization: 'raw-client-token' } });
        expect(await load.json()).toEqual({ settings: 'opaque-base64-payload' });

        const deletion = await app.request('/delete', { headers: { authorization: 'raw-client-token' } });
        expect(await deletion.json()).toEqual({ success: true });
        expect(dependencies.deleted).toEqual(['settings:discord-user', 'sessions:discord-user']);
    });

    test('returns 400 for malformed settings JSON and a string-only settings field', async () => {
        const app = createV1Router(createDependencies());
        const headers = { authorization: 'raw-client-token', 'content-type': 'application/json' };

        const malformed = await app.request('/save', { method: 'POST', headers, body: '{' });
        expect(malformed.status).toBe(400);
        expect(await malformed.json()).toEqual({ error: 'Bad Request' });

        const notString = await app.request('/save', {
            method: 'POST',
            headers,
            body: JSON.stringify({ settings: {} }),
        });
        expect(notString.status).toBe(400);
    });

    test('keeps login, callback token shape, and client id response compatible', async () => {
        const app = createV1Router(createDependencies());

        const login = await app.request('/login');
        expect(login.status).toBe(302);
        expect(login.headers.get('location')).toBe('https://discord.com/oauth2/authorize');

        const callback = await app.request('/callback?code=valid-code');
        expect(callback.status).toBe(200);
        expect(await callback.json()).toEqual({ token: '0123456789abcdef0123456789abcdef' });

        const invalid = await app.request('/callback?code=invalid-code');
        expect(invalid.status).toBe(400);

        const clientId = await app.request('/clientid');
        expect(await clientId.text()).toBe('client-id');
    });
});
