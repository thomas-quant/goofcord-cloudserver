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

    test('does not let in-flight or queued saves restore deleted settings', async () => {
        const dependencies = createDependencies();
        const saveStarted = Promise.withResolvers<void>();
        const finishSave = Promise.withResolvers<void>();
        const deleteStarted = Promise.withResolvers<void>();
        const finishDelete = Promise.withResolvers<void>();
        const queuedAuthenticated = Promise.withResolvers<void>();
        const originalSave = dependencies.settings.save;
        const originalDelete = dependencies.settings.deleteForUser;
        const originalAuthenticate = dependencies.auth.authenticate;
        let revoked = false;
        let deletionEntered = false;
        let authentications = 0;

        dependencies.auth.authenticate = async (authorization) => {
            const result = revoked ? null : await originalAuthenticate(authorization);
            if (++authentications === 3) queuedAuthenticated.resolve();
            return result;
        };
        dependencies.auth.authenticateReadOnly = async (authorization) =>
            revoked ? null : originalAuthenticate(authorization);
        dependencies.auth.revokeAllSessions = async () => { revoked = true; };
        dependencies.settings.save = async (userId, settings) => {
            if (settings === 'in-flight') {
                saveStarted.resolve();
                await finishSave.promise;
            }
            await originalSave(userId, settings);
        };
        dependencies.settings.deleteForUser = async (userId) => {
            deletionEntered = true;
            deleteStarted.resolve();
            await finishDelete.promise;
            await originalDelete(userId);
        };
        const app = createV1Router(dependencies);
        const headers = { authorization: 'raw-client-token', 'content-type': 'application/json' };
        const save = app.request('/save', {
            method: 'POST', headers, body: JSON.stringify({ settings: 'in-flight' }),
        });
        await saveStarted.promise;
        const deletion = app.request('/delete', { headers });
        await new Promise((resolve) => setTimeout(resolve, 0));

        try {
            expect(deletionEntered).toBe(false);
            finishSave.resolve();
            expect((await save).status).toBe(200);
            await deleteStarted.promise;
            const queuedSave = app.request('/save', {
                method: 'POST', headers, body: JSON.stringify({ settings: 'queued' }),
            });
            await queuedAuthenticated.promise;
            finishDelete.resolve();
            expect((await deletion).status).toBe(200);
            expect((await queuedSave).status).toBe(401);
            expect(await dependencies.settings.load('discord-user')).toBeNull();
        } finally {
            finishSave.resolve();
            finishDelete.resolve();
            await Promise.all([save, deletion]);
        }
    });

    test('returns 400 for malformed settings JSON and a string-only settings field', async () => {
        const app = createV1Router(createDependencies());
        const headers = { authorization: 'raw-client-token', 'content-type': 'application/json' };

        const malformed = await app.request('/save', { method: 'POST', headers, body: '{' });
        expect(malformed.status).toBe(400);
        expect(await malformed.json()).toEqual({ error: 'Bad Request' });

        for (const value of [null, false, 123, '', [], { settings: {} }]) {
            const notString = await app.request('/save', {
                method: 'POST', headers, body: JSON.stringify(value),
            });
            expect(notString.status).toBe(400);
            expect(await notString.json()).toEqual({ error: 'Bad Request' });
        }
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
