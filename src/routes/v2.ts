/** Authenticated, read-only version-1 remote-KDF HTTP boundary. */
import { Hono, type Context, type MiddlewareHandler } from 'hono';

import type {
    AppEnv,
    AuthenticationService,
    RouteSecurity,
    SettingsService,
} from '../contracts';
import {
    KDF_ERROR_STATUS,
    kdfErrorResponse,
    isKdfError,
    parseDeriveRequest,
    type KdfErrorCode,
} from '../kdf/contracts';
import type { RemoteKdfService } from '../kdf/service';
import { readJsonBody } from '../security';

export interface V2Dependencies {
    auth: AuthenticationService;
    settings: SettingsService;
    security: RouteSecurity;
    kdf: RemoteKdfService;
}

type KdfStatus = 400 | 401 | 404 | 409 | 422 | 429 | 500;

function errorResponse(context: Context<AppEnv>, code: KdfErrorCode): Response {
    return context.json(kdfErrorResponse(code), KDF_ERROR_STATUS[code] as KdfStatus);
}

function hasQuery(context: Context<AppEnv>): boolean {
    return new URL(context.req.url).search.length > 0;
}

export function createV2Router(dependencies: V2Dependencies): Hono<AppEnv> {
    const app = new Hono<AppEnv>();

    const authenticateReadOnly: MiddlewareHandler<AppEnv> = async (context, next) => {
        const rawAuthorization = context.req.header('authorization');
        if (!rawAuthorization) return errorResponse(context, 'UNAUTHORIZED');

        let session;
        try {
            session = await dependencies.auth.authenticateReadOnly(rawAuthorization);
        } catch {
            return errorResponse(context, 'KDF_FAILED');
        }
        if (!session) return errorResponse(context, 'UNAUTHORIZED');

        context.set('authenticatedSession', session);
        await next();
    };

    app.post(
        '/kdf/derive',
        dependencies.security.kdfIpRateLimit,
        dependencies.security.kdfBodyLimit,
        authenticateReadOnly,
        dependencies.security.kdfDeriveSessionRateLimit,
        async (context) => {
            if (hasQuery(context)) return errorResponse(context, 'INVALID_REQUEST');
            const body = await readJsonBody<unknown>(context);
            if (!body.ok) return errorResponse(context, 'INVALID_REQUEST');
            const request = parseDeriveRequest(body.value);
            if (!request.ok) return errorResponse(context, 'INVALID_REQUEST');

            try {
                const accountId = context.get('authenticatedSession').userId;
                const storedBlob = await dependencies.settings.load(accountId);
                if (storedBlob === null) return errorResponse(context, 'CLOUD_SETTINGS_MISSING');
                const response = await dependencies.kdf.derive(
                    accountId,
                    storedBlob,
                    request.value.cloudEncryptionKey,
                    request.value.channelId,
                );
                return context.json(response);
            } catch (error) {
                return errorResponse(context, isKdfError(error) ? error.code : 'KDF_FAILED');
            }
        },
    );

    app.get(
        '/kdf/revision',
        dependencies.security.kdfIpRateLimit,
        authenticateReadOnly,
        dependencies.security.kdfRevisionSessionRateLimit,
        async (context) => {
            if (hasQuery(context)) return errorResponse(context, 'INVALID_REQUEST');
            try {
                const accountId = context.get('authenticatedSession').userId;
                const storedBlob = await dependencies.settings.load(accountId);
                if (storedBlob === null) return errorResponse(context, 'CLOUD_SETTINGS_MISSING');
                return context.json(dependencies.kdf.revision(storedBlob));
            } catch (error) {
                return errorResponse(context, isKdfError(error) ? error.code : 'KDF_FAILED');
            }
        },
    );

    return app;
}
