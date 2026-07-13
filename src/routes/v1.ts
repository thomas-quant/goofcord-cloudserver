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

    app.post(
        '/save',
        dependencies.security.saveBodyLimit,
        dependencies.security.protectedIpRateLimit,
        authenticate,
        dependencies.security.sessionRateLimit,
        async (context) => {
            let json: { settings?: unknown };
            try {
                json = await context.req.json<{ settings?: unknown }>();
            } catch {
                return context.json({ error: 'Bad Request' }, 400);
            }

            if (typeof json.settings !== 'string') return context.json({ error: 'Bad Request' }, 400);

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
