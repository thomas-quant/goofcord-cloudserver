import { describe, expect, test } from 'bun:test';

import { loadConfig } from '../../src/config';
import type { AuthenticationService, OAuthService, SettingsService } from '../../src/contracts';
import { createApplication } from '../../src/runtime/application';
import { createReadiness } from '../../src/runtime/readiness';
import { createSecurity } from '../../src/security';
import { validEnvironment } from '../helpers/environment';

function createSecureApplication() {
    const settings = new Map<string, string>();
    const auth: AuthenticationService = {
        authenticate: async (rawAuthorization) => rawAuthorization === 'raw-client-token'
            ? { userId: 'discord-user', tokenHash: 'b'.repeat(64) }
            : null,
        createSession: async () => '0123456789abcdef0123456789abcdef',
        revokeAllSessions: async () => undefined,
    };
    const settingsService: SettingsService = {
        save: async (userId, value) => {
            settings.set(userId, value);
        },
        load: async (userId) => settings.get(userId) ?? null,
        deleteForUser: async (userId) => {
            settings.delete(userId);
        },
    };
    const oauth: OAuthService = {
        authorizationUrl: () => 'https://discord.com/oauth2/authorize',
        userIdForCode: async () => ({ kind: 'success', userId: 'discord-user' }),
    };
    const config = loadConfig({
        ...validEnvironment(),
        MAX_REQUEST_BODY_BYTES: '1024',
        IP_RATE_LIMIT: '10',
        CALLBACK_RATE_LIMIT: '10',
        SESSION_RATE_LIMIT: '10',
    });
    const readiness = createReadiness();
    readiness.markReady();

    return createApplication({
        clientId: config.clientId,
        auth,
        settings: settingsService,
        oauth,
        security: createSecurity(config),
        readiness,
        mongoConnection: { readyState: 1 },
    });
}

describe('hardened application composition', () => {
    test('applies global headers and preserves the callback token response', async () => {
        const app = createSecureApplication();
        const response = await app.fetch(
            new Request('http://localhost/v1/callback?code=valid-code'),
            { directPeerAddress: '127.0.0.1' },
        );

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ token: '0123456789abcdef0123456789abcdef' });
        expect(response.headers.get('cache-control')).toBe('no-store');
        expect(response.headers.get('pragma')).toBe('no-cache');
        expect(response.headers.get('referrer-policy')).toBe('no-referrer');
        expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    test('routes malformed settings JSON through the body boundary before persistence', async () => {
        const app = createSecureApplication();
        const response = await app.fetch(
            new Request('http://localhost/v1/save', {
                method: 'POST',
                headers: {
                    authorization: 'raw-client-token',
                    'content-type': 'application/json',
                },
                body: '{',
            }),
            { directPeerAddress: '127.0.0.1' },
        );

        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({ error: 'Bad Request' });
        expect(response.headers.get('cache-control')).toBe('no-store');
    });
});
