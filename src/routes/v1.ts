import { Hono, type MiddlewareHandler } from 'hono';

import type { AppEnv, AuthenticatedSession, V1Dependencies } from '../contracts';

export const UNAUTHORIZED_ERROR = 'Unauthorized. Please authenticate again';
const INTERNAL_SERVER_ERROR = 'Internal Server Error';

export function createV1Router(dependencies: V1Dependencies): Hono<AppEnv> {
    const app = new Hono<AppEnv>();

    const authenticate: MiddlewareHandler<AppEnv> = async (context, next) => {
        const rawAuthorization = context.req.header('authorization');
        if (!rawAuthorization) return context.json({ error: UNAUTHORIZED_ERROR }, 401);

        const session = await dependencies.auth.authenticate(rawAuthorization);
        if (!session) return context.json({ error: UNAUTHORIZED_ERROR }, 401);

        context.set('authenticatedSession', session);
        await next();
    };

    const session = (context: { get: (key: 'authenticatedSession') => AuthenticatedSession }) =>
        context.get('authenticatedSession');
    const accountWrites = new Map<string, Promise<void>>();

    const serializeAccountWrite: MiddlewareHandler<AppEnv> = async (context, next) => {
        const { userId, tokenHash } = session(context);
        const previous = accountWrites.get(userId) ?? Promise.resolve();
        let release!: () => void;
        const current = new Promise<void>((resolve) => { release = resolve; });
        accountWrites.set(userId, current);
        await previous;

        try {
            const authorization = context.req.header('authorization');
            const activeSession = authorization
                ? await dependencies.auth.authenticateReadOnly(authorization)
                : null;
            if (activeSession?.userId !== userId || activeSession.tokenHash !== tokenHash) {
                return context.json({ error: UNAUTHORIZED_ERROR }, 401);
            }
            await next();
        } finally {
            release();
            if (accountWrites.get(userId) === current) accountWrites.delete(userId);
        }
    };

    app.post(
        '/save',
        dependencies.security.protectedIpRateLimit,
        dependencies.security.saveBodyLimit,
        authenticate,
        dependencies.security.sessionRateLimit,
        serializeAccountWrite,
        async (context) => {
            let json: { settings?: unknown };
            try {
                json = await context.req.json<{ settings?: unknown }>();
            } catch {
                return context.json({ error: 'Bad Request' }, 400);
            }

            if (!json || typeof json.settings !== 'string') return context.json({ error: 'Bad Request' }, 400);

            try {
                await dependencies.settings.save(session(context).userId, json.settings);
                return context.json({ success: true });
            } catch {
                return context.json({ error: INTERNAL_SERVER_ERROR }, 500);
            }
        },
    );

    app.get(
        '/load',
        dependencies.security.protectedIpRateLimit,
        authenticate,
        dependencies.security.sessionRateLimit,
        async (context) => {
            try {
                const settings = await dependencies.settings.load(session(context).userId);
                return context.json({ settings: settings ?? '' });
            } catch {
                return context.json({ error: INTERNAL_SERVER_ERROR }, 500);
            }
        },
    );

    app.get(
        '/delete',
        dependencies.security.protectedIpRateLimit,
        authenticate,
        dependencies.security.sessionRateLimit,
        serializeAccountWrite,
        async (context) => {
            try {
                const userId = session(context).userId;
                await dependencies.settings.deleteForUser(userId);
                await dependencies.auth.revokeAllSessions(userId);
                return context.json({ success: true });
            } catch {
                return context.json({ error: INTERNAL_SERVER_ERROR }, 500);
            }
        },
    );

    app.get('/login', (context) => context.redirect(dependencies.oauth.authorizationUrl()));

    app.get('/callback', dependencies.security.callbackIpRateLimit, async (context) => {
        const code = context.req.query('code');
        if (!code) return context.json({ error: 'OAuth2 code not found' }, 400);

        try {
            const result = await dependencies.oauth.userIdForCode(code);
            if (result.kind === 'invalid_code') {
                return context.json({ error: 'Failed to obtain token. Is the OAuth2 code correct?' }, 400);
            }

            const token = await dependencies.auth.createSession(result.userId);
            return context.json({ token });
        } catch {
            return context.json({ error: INTERNAL_SERVER_ERROR }, 500);
        }
    });

    app.get('/clientid', (context) => context.body(dependencies.clientId));
    app.get('/ping', (context) => context.text('Pong!'));

    return app;
}
