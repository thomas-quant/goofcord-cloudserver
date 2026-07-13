import { describe, expect, test } from 'bun:test';
import type { MiddlewareHandler } from 'hono';

import { createApplication } from '../../src/runtime/application';
import type {
    AppEnv,
    AuthenticationService,
    OAuthService,
    SecurityService,
    SettingsService,
} from '../../src/contracts';
import { createReadiness } from '../../src/runtime/readiness';

const continueRequest: MiddlewareHandler<AppEnv> = async (_context, next) => next();

function createSecurity(): SecurityService {
    return {
        application: {
            resolveClientRequest: continueRequest,
            enforceHttps: continueRequest,
            securityHeaders: continueRequest,
            onError: () => new Response('Internal Server Error', { status: 500 }),
        },
        routes: {
            saveBodyLimit: continueRequest,
            protectedIpRateLimit: continueRequest,
            callbackIpRateLimit: continueRequest,
            sessionRateLimit: continueRequest,
        },
    };
}

function createApplicationDependencies(readyState: number) {
    const auth: AuthenticationService = {
        authenticate: async () => null,
        createSession: async () => '0123456789abcdef0123456789abcdef',
        revokeAllSessions: async () => undefined,
    };
    const settings: SettingsService = {
        save: async () => undefined,
        load: async () => null,
        deleteForUser: async () => undefined,
    };
    const oauth: OAuthService = {
        authorizationUrl: () => 'https://discord.com/oauth2/authorize',
        userIdForCode: async () => ({ kind: 'invalid_code' }),
    };
    const readiness = createReadiness();

    return {
        dependencies: {
            clientId: 'client-id',
            auth,
            settings,
            oauth,
            security: createSecurity(),
            readiness,
            mongoConnection: { readyState },
        },
        readiness,
    };
}

describe('readiness endpoint', () => {
    test('applies application security before the unauthenticated health limiter', async () => {
        const order: string[] = [];
        const record = (name: string): MiddlewareHandler<AppEnv> => async (_context, next) => {
            order.push(name);
            await next();
        };
        const { dependencies, readiness } = createApplicationDependencies(1);
        dependencies.security = {
            application: {
                resolveClientRequest: record('resolveClientRequest'),
                enforceHttps: record('enforceHttps'),
                securityHeaders: record('securityHeaders'),
                onError: () => new Response('Internal Server Error', { status: 500 }),
            },
            routes: {
                saveBodyLimit: continueRequest,
                protectedIpRateLimit: record('protectedIpRateLimit'),
                callbackIpRateLimit: continueRequest,
                sessionRateLimit: continueRequest,
            },
        };
        readiness.markReady();

        const response = await createApplication(dependencies).request('/healthz');

        expect(response.status).toBe(200);
        expect(order).toEqual([
            'resolveClientRequest',
            'enforceHttps',
            'securityHeaders',
            'protectedIpRateLimit',
        ]);
    });

    test('returns 503 until startup completes', async () => {
        const { dependencies } = createApplicationDependencies(1);
        const response = await createApplication(dependencies).request('/healthz');

        expect(response.status).toBe(503);
        expect(await response.text()).toBe('Service Unavailable');
    });

    test('returns 200 only while MongoDB is connected', async () => {
        const { dependencies, readiness } = createApplicationDependencies(1);
        readiness.markReady();
        const app = createApplication(dependencies);

        expect((await app.request('/healthz')).status).toBe(200);
        dependencies.mongoConnection.readyState = 3;
        expect((await app.request('/healthz')).status).toBe(503);
    });
});
