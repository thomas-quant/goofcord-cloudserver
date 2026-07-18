import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';

import type { AppConfig } from '../../src/config';
import type { AppEnv } from '../../src/contracts';
import { createSecurity, readJsonBody } from '../../src/security';

const config = (overrides: Partial<AppConfig> = {}): AppConfig => ({
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'http://localhost:3000',
    mongoUri: 'mongodb://127.0.0.1:27017/goofcord-test',
    port: 3000,
    mongoServerSelectionTimeoutMs: 5_000,
    maxRequestBodyBytes: 1024 * 1024,
    sessionTouchIntervalMs: 15 * 60 * 1_000,
    enforceHttps: false,
    trustedProxyCidrs: [],
    rateLimitMaxKeys: 100,
    ipRateLimit: { limit: 100, windowMs: 60_000 },
    callbackRateLimit: { limit: 20, windowMs: 60_000 },
    sessionRateLimit: { limit: 60, windowMs: 60_000 },
    kdfGlobalConcurrency: 1,
    kdfJobTimeoutMs: 30_000,
    kdfAllowInsecureLocalhost: false,
    ...overrides,
});

function application(security = createSecurity(config())): Hono<AppEnv> {
    const app = new Hono<AppEnv>();
    app.onError(security.application.onError);
    app.use('*', security.application.resolveClientRequest);
    app.use('*', security.application.enforceHttps);
    app.use('*', security.application.securityHeaders);
    return app;
}

function request(
    path: string,
    init: RequestInit = {},
    directPeerAddress = '198.51.100.10',
): [Request, AppEnv['Bindings']] {
    return [new Request(`http://service.test${path}`, init), { directPeerAddress }];
}

describe('save body limit', () => {
    test('accepts a body exactly at the limit and rejects one byte over', async () => {
        const security = createSecurity(config({ maxRequestBodyBytes: 4 }));
        const app = application(security);
        app.post('/save', security.routes.saveBodyLimit, async (context) => context.text(await context.req.text()));

        const exact = await app.fetch(...request('/save', { method: 'POST', body: 'four' }));
        expect(exact.status).toBe(200);
        expect(await exact.text()).toBe('four');

        const tooLarge = await app.fetch(...request('/save', { method: 'POST', body: 'five!' }));
        expect(tooLarge.status).toBe(413);
        expect(await tooLarge.json()).toEqual({ error: 'Payload Too Large' });
    });

    test('counts UTF-8 stream bytes despite missing or false Content-Length', async () => {
        const security = createSecurity(config({ maxRequestBodyBytes: 3 }));
        const app = application(security);
        app.post('/save', security.routes.saveBodyLimit, (context) => context.text('accepted'));

        const missingLength = await app.fetch(...request('/save', {
            method: 'POST',
            body: new ReadableStream({
                start(controller) {
                    controller.enqueue(new TextEncoder().encode('éé'));
                    controller.close();
                },
            }),
        }));
        expect(missingLength.status).toBe(413);

        const falseLength = await app.fetch(...request('/save', {
            method: 'POST',
            headers: { 'Content-Length': '1' },
            body: 'four',
        }));
        expect(falseLength.status).toBe(413);
    });

    test('offers routes a safe malformed JSON result', async () => {
        const security = createSecurity(config());
        const app = application(security);
        app.post('/save', security.routes.saveBodyLimit, async (context) => {
            const body = await readJsonBody<{ settings?: unknown }>(context);
            if (!body.ok || typeof body.value.settings !== 'string') {
                return context.json({ error: 'Bad Request' }, 400);
            }
            return context.json({ settings: body.value.settings });
        });

        const malformed = await app.fetch(...request('/save', { method: 'POST', body: '{"settings"' }));
        expect(malformed.status).toBe(400);
        expect(await malformed.json()).toEqual({ error: 'Bad Request' });
    });
});

describe('rate limits', () => {
    test('uses separate IP, callback, and token-hash session buckets', async () => {
        const security = createSecurity(config({
            ipRateLimit: { limit: 2, windowMs: 60_000 },
            callbackRateLimit: { limit: 1, windowMs: 60_000 },
            sessionRateLimit: { limit: 1, windowMs: 60_000 },
        }));
        const app = application(security);
        app.get('/protected', security.routes.protectedIpRateLimit, async (context, next) => {
            context.set('authenticatedSession', { userId: 'user', tokenHash: context.req.header('x-token') ?? '' });
            await next();
        }, security.routes.sessionRateLimit, (context) => context.text('ok'));
        app.get('/callback', security.routes.callbackIpRateLimit, (context) => context.text('ok'));

        expect((await app.fetch(...request('/protected', { headers: { 'x-token': 'hash-a' } }, '198.51.100.1'))).status).toBe(200);
        const sameSessionDifferentIp = await app.fetch(...request('/protected', { headers: { 'x-token': 'hash-a' } }, '198.51.100.2'));
        expect(sameSessionDifferentIp.status).toBe(429);
        expect(sameSessionDifferentIp.headers.get('Retry-After')).toMatch(/^\d+$/);

        expect((await app.fetch(...request('/callback', {}, '198.51.100.1'))).status).toBe(200);
        expect((await app.fetch(...request('/callback', {}, '198.51.100.1'))).status).toBe(429);
    });

    test('bounds keys and removes expired buckets', async () => {
        const security = createSecurity(config({
            rateLimitMaxKeys: 2,
            ipRateLimit: { limit: 1, windowMs: 20 },
        }));
        const app = application(security);
        app.get('/protected', security.routes.protectedIpRateLimit, (context) => context.text('ok'));

        expect((await app.fetch(...request('/protected', {}, '198.51.100.1'))).status).toBe(200);
        expect((await app.fetch(...request('/protected', {}, '198.51.100.2'))).status).toBe(200);
        expect((await app.fetch(...request('/protected', {}, '198.51.100.3'))).status).toBe(429);

        await Bun.sleep(30);
        expect((await app.fetch(...request('/protected', {}, '198.51.100.3'))).status).toBe(200);
    });
});

describe('trusted client request and HTTPS', () => {
    test('ignores forged forwarding headers from an untrusted direct peer', async () => {
        const app = application(createSecurity(config({ trustedProxyCidrs: ['10.0.0.0/8'] })));
        app.get('/request', (context) => context.json(context.get('clientRequest')));

        const response = await app.fetch(...request('/request', {
            headers: {
                'X-Forwarded-For': '203.0.113.8',
                'X-Forwarded-Proto': 'https',
            },
        }, '198.51.100.10'));
        expect(await response.json()).toMatchObject({
            ip: '198.51.100.10',
            isSecure: false,
            trustedProxy: false,
        });
    });

    test('accepts one forwarded hop only from a configured proxy', async () => {
        const app = application(createSecurity(config({ trustedProxyCidrs: ['10.0.0.0/8'] })));
        app.get('/request', (context) => context.json(context.get('clientRequest')));

        const response = await app.fetch(...request('/request', {
            headers: {
                'X-Forwarded-For': '203.0.113.8',
                'X-Forwarded-Proto': 'https',
            },
        }, '10.4.5.6'));
        expect(await response.json()).toMatchObject({
            ip: '203.0.113.8',
            isSecure: true,
            directPeerAddress: '10.4.5.6',
            trustedProxy: true,
        });

        const chained = await app.fetch(...request('/request', {
            headers: { 'X-Forwarded-For': '203.0.113.8, 198.51.100.2' },
        }, '10.4.5.6'));
        expect((await chained.json() as { ip: string }).ip).toBe('10.4.5.6');
    });

    test('rejects insecure non-local requests and emits HSTS only for secure requests', async () => {
        const security = createSecurity(config({ enforceHttps: true, trustedProxyCidrs: ['10.0.0.0/8'] }));
        const app = application(security);
        app.get('/request', (context) => context.text('ok'));

        const insecure = await app.fetch(...request('/request', {}, '198.51.100.10'));
        expect(insecure.status).toBe(400);
        expect(insecure.headers.get('Strict-Transport-Security')).toBeNull();
        expect(insecure.headers.get('X-Content-Type-Options')).toBe('nosniff');

        const local = await app.fetch(...request('/request', {}, '127.0.0.1'));
        expect(local.status).toBe(200);
        expect(local.headers.get('Strict-Transport-Security')).toBeNull();

        const forgedLocalForward = await app.fetch(...request('/request', {
            headers: { 'X-Forwarded-For': '127.0.0.1' },
        }, '10.4.5.6'));
        expect(forgedLocalForward.status).toBe(400);

        const secure = await app.fetch(...request('/request', {
            headers: { 'X-Forwarded-Proto': 'https' },
        }, '10.4.5.6'));
        expect(secure.status).toBe(200);
        expect(secure.headers.get('Strict-Transport-Security')).toBe('max-age=31536000; includeSubDomains');
        expect(secure.headers.get('Cache-Control')).toBe('no-store');
        expect(secure.headers.get('Referrer-Policy')).toBe('no-referrer');
    });
});

describe('sanitized errors', () => {
    test('does not expose exception details', async () => {
        const app = application();
        app.get('/failure', () => {
            throw new Error('database password should not be exposed');
        });

        const response = await app.fetch(...request('/failure'));
        expect(response.status).toBe(500);
        expect(await response.json()).toEqual({ error: 'Internal Server Error' });
        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    });

    test('uses the frozen KDF error for uncaught pre-handler failures only on exact KDF paths', async () => {
        const app = application();
        app.get('/v2/kdf/failure', () => {
            throw new Error('secret pre-handler detail');
        });
        app.get('/v2/kdf-lookalike/failure', () => {
            throw new Error('legacy detail');
        });

        const kdf = await app.fetch(
            new Request('https://service.test/v2/kdf/failure'),
            { directPeerAddress: '198.51.100.10' },
        );
        expect(kdf.status).toBe(500);
        expect(await kdf.json()).toEqual({ version: 1, error: { code: 'KDF_FAILED' } });

        const legacy = await app.fetch(...request('/v2/kdf-lookalike/failure'));
        expect(await legacy.json()).toEqual({ error: 'Internal Server Error' });
    });
});

describe('remote KDF admission controls', () => {
    test('enforces KDF HTTPS under both global modes and preserves legacy HTTPS bodies', async () => {
        for (const enforceHttps of [false, true]) {
            const security = createSecurity(config({ enforceHttps }));
            const app = application(security);
            app.get('/v2/kdf/revision', (context) => context.text('unreachable'));
            app.get('/v1/ping', (context) => context.text('Pong!'));

            const kdf = await app.fetch(...request('/v2/kdf/revision', {}, '198.51.100.10'));
            expect(kdf.status).toBe(400);
            expect(await kdf.json()).toEqual({ version: 1, error: { code: 'INVALID_REQUEST' } });

            const v1 = await app.fetch(...request('/v1/ping', {}, '198.51.100.10'));
            expect(v1.status).toBe(enforceHttps ? 400 : 200);
            if (enforceHttps) expect(await v1.json()).toEqual({ error: 'HTTPS Required' });
        }
    });

    test('allows insecure KDF only for direct loopback with the explicit flag', async () => {
        const security = createSecurity(config({ kdfAllowInsecureLocalhost: true }));
        const app = application(security);
        app.get('/v2/kdf/revision', (context) => context.text('ok'));

        expect((await app.fetch(...request('/v2/kdf/revision', {}, '127.0.0.1'))).status).toBe(200);
        const external = await app.fetch(...request('/v2/kdf/revision', {}, '198.51.100.10'));
        expect(external.status).toBe(400);
    });

    test('enforces the exact 4096-byte content-length and streamed body bound', async () => {
        const security = createSecurity(config());
        const app = application(security);
        app.post('/v2/kdf/body', security.routes.kdfBodyLimit, async (context) => {
            return context.text(String((await context.req.arrayBuffer()).byteLength));
        });

        const exact = await app.fetch(new Request('https://service.test/v2/kdf/body', {
            method: 'POST',
            body: 'x'.repeat(4096),
        }), { directPeerAddress: '198.51.100.10' });
        expect(exact.status).toBe(200);
        expect(await exact.text()).toBe('4096');

        for (const body of [
            'x'.repeat(4097),
            new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new Uint8Array(4096));
                    controller.enqueue(new Uint8Array(1));
                    controller.close();
                },
            }),
        ]) {
            const response = await app.fetch(new Request('https://service.test/v2/kdf/body', {
                method: 'POST',
                body,
            }), { directPeerAddress: '198.51.100.10' });
            expect(response.status).toBe(400);
            expect(await response.json()).toEqual({ version: 1, error: { code: 'INVALID_REQUEST' } });
        }
    });

    test('uses fixed shared-IP and separate token-hash thresholds', async () => {
        let now = 1_000_000;
        const ipSecurity = createSecurity(config(), { now: () => now });
        const ipApp = application(ipSecurity);
        ipApp.get('/v2/kdf/ip', ipSecurity.routes.kdfIpRateLimit, (context) => context.text('ok'));
        for (let count = 1; count <= 13; count += 1) {
            const response = await ipApp.fetch(
                new Request('https://service.test/v2/kdf/ip'),
                { directPeerAddress: '198.51.100.20' },
            );
            expect(response.status).toBe(count <= 12 ? 200 : 429);
            if (count === 13) {
                expect(await response.json()).toEqual({ version: 1, error: { code: 'KDF_BUSY' } });
            }
        }
        now += 60_001;
        expect((await ipApp.fetch(
            new Request('https://service.test/v2/kdf/ip'),
            { directPeerAddress: '198.51.100.20' },
        )).status).toBe(200);

        const tokenSecurity = createSecurity(config(), { now: () => now });
        const tokenApp = application(tokenSecurity);
        const setSession = async (context: Parameters<typeof tokenSecurity.routes.kdfDeriveSessionRateLimit>[0], next: () => Promise<void>) => {
            context.set('authenticatedSession', { userId: 'user', tokenHash: 'a'.repeat(64) });
            await next();
        };
        tokenApp.get('/v2/kdf/derive-rate', setSession, tokenSecurity.routes.kdfDeriveSessionRateLimit,
            (context) => context.text('ok'));
        tokenApp.get('/v2/kdf/revision-rate', setSession, tokenSecurity.routes.kdfRevisionSessionRateLimit,
            (context) => context.text('ok'));

        for (let count = 1; count <= 5; count += 1) {
            const response = await tokenApp.request('https://service.test/v2/kdf/derive-rate');
            expect(response.status).toBe(count <= 4 ? 200 : 429);
        }
        now += 60_001;
        expect((await tokenApp.request('https://service.test/v2/kdf/derive-rate')).status).toBe(200);
        for (let count = 1; count <= 13; count += 1) {
            const response = await tokenApp.request('https://service.test/v2/kdf/revision-rate');
            expect(response.status).toBe(count <= 12 ? 200 : 429);
        }
    });

    test('does not enter body middleware before HTTPS or after IP exhaustion', async () => {
        const security = createSecurity(config());
        const app = application(security);
        let bodyEntries = 0;
        const countedBody: typeof security.routes.kdfBodyLimit = async (context, next) => {
            bodyEntries += 1;
            await security.routes.kdfBodyLimit(context, next);
        };
        app.post('/v2/kdf/order', security.routes.kdfIpRateLimit, countedBody, (context) => context.text('ok'));

        const insecure = await app.fetch(
            new Request('http://service.test/v2/kdf/order', { method: 'POST', body: 'secret' }),
            { directPeerAddress: '198.51.100.30' },
        );
        expect(insecure.status).toBe(400);
        expect(bodyEntries).toBe(0);

        for (let count = 1; count <= 12; count += 1) {
            const response = await app.fetch(
                new Request('https://service.test/v2/kdf/order', { method: 'POST', body: 'x' }),
                { directPeerAddress: '198.51.100.31' },
            );
            expect(response.status).toBe(200);
        }
        expect(bodyEntries).toBe(12);

        const limited = await app.fetch(
            new Request('https://service.test/v2/kdf/order', { method: 'POST', body: 'must-not-be-read' }),
            { directPeerAddress: '198.51.100.31' },
        );
        expect(limited.status).toBe(429);
        expect(bodyEntries).toBe(12);
    });
});
