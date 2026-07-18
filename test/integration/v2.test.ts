import { afterEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import type { MiddlewareHandler } from 'hono';

import { loadConfig } from '../../src/config';
import type {
    AppEnv,
    AuthenticationService,
    OAuthService,
    SecurityService,
    SettingsService,
} from '../../src/contracts';
import { KdfError, type KdfDeriveResponse, type KdfRevisionResponse } from '../../src/kdf/contracts';
import { createKdfWorkerPool } from '../../src/kdf/pool';
import { createRemoteKdfService, type RemoteKdfService } from '../../src/kdf/service';
import { createApplication } from '../../src/runtime/application';
import { createReadiness } from '../../src/runtime/readiness';
import { createSecurity } from '../../src/security';
import { validEnvironment } from '../helpers/environment';

const KEY = 'WNRTGTkvrju+EwmAg1mCEem36E040hCwFKVkROLN6AQ=';
const REVISION = 'A'.repeat(43);

interface CloudFixtures {
    encrypted: { cloudEncryptionKey: string; blob: string };
}

const fixtures = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/cloud-blobs-v1.json', import.meta.url),
    'utf8',
)) as CloudFixtures;

class StubKdf implements RemoteKdfService {
    readonly derives: Array<{ accountId: string; blob: string; cloudKey: string; channelId: string }> = [];
    readonly revisions: string[] = [];
    failure: KdfError | undefined;

    async initialize(): Promise<void> {}

    async derive(accountId: string, blob: string, cloudKey: string, channelId: string): Promise<KdfDeriveResponse> {
        this.derives.push({ accountId, blob, cloudKey, channelId });
        if (this.failure) throw this.failure;
        return { version: 1, settingsRevision: REVISION, keys: [{ slot: 0, key: KEY }] };
    }

    revision(blob: string): KdfRevisionResponse {
        this.revisions.push(blob);
        return { version: 1, settingsRevision: REVISION };
    }

    async close(): Promise<void> {}
}

interface Harness {
    app: ReturnType<typeof createApplication>;
    kdf: StubKdf;
    loads: string[];
    writes: string[];
    readOnlyAuth: string[];
}

function harness(options: {
    settings?: Record<string, string>;
    enforceHttps?: boolean;
    allowLocalhost?: boolean;
    security?: SecurityService;
    kdf?: StubKdf;
} = {}): Harness {
    const loads: string[] = [];
    const writes: string[] = [];
    const readOnlyAuth: string[] = [];
    const stored = options.settings ?? {
        'account-a': 'opaque-account-a',
        'account-b': 'opaque-account-b',
    };
    const auth: AuthenticationService = {
        authenticate: async () => {
            writes.push('session-touch');
            throw new Error('v2 must not call touching authentication');
        },
        authenticateReadOnly: async (rawAuthorization) => {
            readOnlyAuth.push(rawAuthorization);
            if (rawAuthorization === 'token-a') return { userId: 'account-a', tokenHash: 'a'.repeat(64) };
            if (rawAuthorization === 'token-b') return { userId: 'account-b', tokenHash: 'b'.repeat(64) };
            return null;
        },
        createSession: async () => '0123456789abcdef0123456789abcdef',
        revokeAllSessions: async () => {
            writes.push('session-revoke');
        },
    };
    const settings: SettingsService = {
        save: async () => {
            writes.push('settings-save');
        },
        load: async (userId) => {
            loads.push(userId);
            return stored[userId] ?? null;
        },
        deleteForUser: async () => {
            writes.push('settings-delete');
        },
    };
    const oauth: OAuthService = {
        authorizationUrl: () => 'https://discord.com/oauth2/authorize',
        userIdForCode: async () => ({ kind: 'invalid_code' }),
    };
    const config = loadConfig({
        ...validEnvironment(),
        ENFORCE_HTTPS: String(options.enforceHttps ?? false),
        KDF_ALLOW_INSECURE_LOCALHOST: String(options.allowLocalhost ?? false),
    });
    const readiness = createReadiness();
    readiness.markReady();
    const kdf = options.kdf ?? new StubKdf();
    return {
        app: createApplication({
            clientId: config.clientId,
            auth,
            settings,
            oauth,
            security: options.security ?? createSecurity(config),
            kdf,
            readiness,
            mongoConnection: { readyState: 1 },
        }),
        kdf,
        loads,
        writes,
        readOnlyAuth,
    };
}

function deriveRequest(body: unknown, token = 'token-a'): Request {
    return new Request('https://service.test/v2/kdf/derive', {
        method: 'POST',
        headers: { authorization: token, 'content-type': 'application/json' },
        body: typeof body === 'string' ? body : JSON.stringify(body),
    });
}

async function fetch(app: Harness['app'], request: Request, peer = '198.51.100.10'): Promise<Response> {
    return app.fetch(request, { directPeerAddress: peer });
}

afterEach(() => {
    mock.restore();
});

describe('authenticated remote KDF v2 routes', () => {
    test('binds settings exclusively to read-only authenticated identity', async () => {
        const current = harness();
        const response = await fetch(current.app, deriveRequest({
            version: 1,
            channelId: '1234567890123456789',
            cloudEncryptionKey: 'cloud-a',
        }));

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({
            version: 1,
            settingsRevision: REVISION,
            keys: [{ slot: 0, key: KEY }],
        });
        expect(current.loads).toEqual(['account-a']);
        expect(current.kdf.derives).toEqual([{
            accountId: 'account-a',
            blob: 'opaque-account-a',
            cloudKey: 'cloud-a',
            channelId: '1234567890123456789',
        }]);
        expect(current.readOnlyAuth).toEqual(['token-a']);
        expect(current.writes).toEqual([]);

        const forbiddenBody = await fetch(current.app, deriveRequest({
            version: 1,
            channelId: '1',
            cloudEncryptionKey: 'cloud-a',
            userId: 'account-b',
        }));
        expect(forbiddenBody.status).toBe(400);
        expect(await forbiddenBody.json()).toEqual({ version: 1, error: { code: 'INVALID_REQUEST' } });

        const forbiddenQuery = await fetch(current.app, new Request(
            'https://service.test/v2/kdf/revision?userId=account-b',
            { headers: { authorization: 'token-a' } },
        ));
        expect(forbiddenQuery.status).toBe(400);
        expect(current.loads).toEqual(['account-a']);
    });

    test('returns exact stable bodies for request, auth, settings, and service failures', async () => {
        const cases: Array<{
            name: string;
            request: Request;
            status: number;
            code: string;
            prepare?: (current: Harness) => void;
            settings?: Record<string, string>;
        }> = [
            { name: 'invalid json', request: deriveRequest('{'), status: 400, code: 'INVALID_REQUEST' },
            { name: 'token only', request: deriveRequest({ version: 1, channelId: '1' }), status: 400, code: 'INVALID_REQUEST' },
            { name: 'unauthorized', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }, 'bad'), status: 401, code: 'UNAUTHORIZED' },
            { name: 'missing settings', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }), status: 404, code: 'CLOUD_SETTINGS_MISSING', settings: {} },
            { name: 'passwordless', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }), status: 409, code: 'PASSWORDS_NOT_SYNCED', prepare: (current) => { current.kdf.failure = new KdfError('PASSWORDS_NOT_SYNCED'); } },
            { name: 'wrong key', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }), status: 422, code: 'CLOUD_DECRYPT_FAILED', prepare: (current) => { current.kdf.failure = new KdfError('CLOUD_DECRYPT_FAILED'); } },
            { name: 'busy', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }), status: 429, code: 'KDF_BUSY', prepare: (current) => { current.kdf.failure = new KdfError('KDF_BUSY'); } },
            { name: 'failed', request: deriveRequest({ version: 1, channelId: '1', cloudEncryptionKey: 'x' }), status: 500, code: 'KDF_FAILED', prepare: (current) => { current.kdf.failure = new KdfError('KDF_FAILED'); } },
        ];

        for (const item of cases) {
            const current = harness({ settings: item.settings });
            item.prepare?.(current);
            const response = await fetch(current.app, item.request);
            expect(response.status, item.name).toBe(item.status);
            expect(await response.json(), item.name).toEqual({ version: 1, error: { code: item.code } });
        }
    });

    test('revision loads only the authenticated blob and never invokes derive/decrypt', async () => {
        const current = harness();
        const response = await fetch(current.app, new Request('https://service.test/v2/kdf/revision', {
            headers: { authorization: 'token-b' },
        }));
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ version: 1, settingsRevision: REVISION });
        expect(current.loads).toEqual(['account-b']);
        expect(current.kdf.revisions).toEqual(['opaque-account-b']);
        expect(current.kdf.derives).toHaveLength(0);
        expect(current.writes).toEqual([]);
    });

    test('applies logical middleware order and maps forced pre-handler exceptions globally', async () => {
        const realSecurity = createSecurity(loadConfig(validEnvironment()));
        const order: string[] = [];
        const record = (name: string, delegate: MiddlewareHandler<AppEnv>): MiddlewareHandler<AppEnv> =>
            async (context, next) => {
                order.push(name);
                await delegate(context, next);
            };
        const security: SecurityService = {
            application: {
                ...realSecurity.application,
                enforceHttps: record('HTTPS', realSecurity.application.enforceHttps),
            },
            routes: {
                ...realSecurity.routes,
                kdfIpRateLimit: record('IP', realSecurity.routes.kdfIpRateLimit),
                kdfBodyLimit: record('body', realSecurity.routes.kdfBodyLimit),
                kdfDeriveSessionRateLimit: record('token', realSecurity.routes.kdfDeriveSessionRateLimit),
            },
        };
        const current = harness({ security });
        current.readOnlyAuth.push = ((value: string) => {
            order.push('auth');
            return Array.prototype.push.call(current.readOnlyAuth, value);
        }) as typeof current.readOnlyAuth.push;
        current.loads.push = ((value: string) => {
            order.push('JSON/handler');
            return Array.prototype.push.call(current.loads, value);
        }) as typeof current.loads.push;

        const response = await fetch(current.app, deriveRequest({
            version: 1,
            channelId: '1',
            cloudEncryptionKey: 'x',
        }));
        expect(response.status).toBe(200);
        expect(order).toEqual(['HTTPS', 'IP', 'body', 'auth', 'token', 'JSON/handler']);

        const throwingSecurity: SecurityService = {
            application: realSecurity.application,
            routes: {
                ...realSecurity.routes,
                kdfIpRateLimit: () => {
                    throw new Error('secret forced pre-handler failure');
                },
            },
        };
        const failed = harness({ security: throwingSecurity });
        const failure = await fetch(failed.app, deriveRequest({
            version: 1,
            channelId: '1',
            cloudEncryptionKey: 'x',
        }));
        expect(failure.status).toBe(500);
        expect(await failure.json()).toEqual({ version: 1, error: { code: 'KDF_FAILED' } });
    });

    test('enforces KDF HTTPS in the full application without changing v1 behavior', async () => {
        for (const enforceHttps of [false, true]) {
            const current = harness({ enforceHttps });
            const insecure = await fetch(current.app, new Request('http://service.test/v2/kdf/revision', {
                headers: { authorization: 'token-a' },
            }));
            expect(insecure.status).toBe(400);
            expect(await insecure.json()).toEqual({ version: 1, error: { code: 'INVALID_REQUEST' } });

            const v1 = await fetch(current.app, new Request('http://service.test/v1/ping'));
            expect(v1.status).toBe(enforceHttps ? 400 : 200);
            if (!enforceHttps) expect(await v1.text()).toBe('Pong!');
        }
    });

    test('rate limits authenticated derives at four per token without reflecting secrets', async () => {
        const log = spyOn(console, 'log').mockImplementation(() => undefined);
        const error = spyOn(console, 'error').mockImplementation(() => undefined);
        const current = harness();
        const secret = 'unique-cloud-secret-marker';
        for (let count = 1; count <= 5; count += 1) {
            const response = await fetch(current.app, deriveRequest({
                version: 1,
                channelId: '987654321',
                cloudEncryptionKey: secret,
            }));
            expect(response.status).toBe(count <= 4 ? 200 : 429);
            if (count === 5) {
                const body = JSON.stringify(await response.json());
                expect(body).not.toContain(secret);
                expect(body).not.toContain('987654321');
                expect(body).not.toContain(KEY);
            }
        }
        const output = JSON.stringify([...log.mock.calls, ...error.mock.calls]);
        expect(output).not.toContain(secret);
        expect(output).not.toContain('987654321');
        expect(output).not.toContain(KEY);
    });

    test('returns the exact vector through the full real decoder and worker path', async () => {
        const pool = createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 30000 });
        const kdf = createRemoteKdfService(pool);
        await kdf.initialize();
        try {
            const current = harness({
                settings: { 'account-a': fixtures.encrypted.blob },
                kdf: kdf as StubKdf,
            });
            const response = await fetch(current.app, deriveRequest({
                version: 1,
                channelId: '1234567890123456789',
                cloudEncryptionKey: fixtures.encrypted.cloudEncryptionKey,
            }));
            expect(response.status).toBe(200);
            const body = await response.json() as KdfDeriveResponse;
            expect(body.keys[0]).toEqual({ slot: 0, key: KEY });
            expect(body.keys.map((entry) => entry.slot)).toEqual([0, 1]);
        } finally {
            await kdf.close();
        }
    }, 90_000);
});
