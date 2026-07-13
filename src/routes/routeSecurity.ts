import type { MiddlewareHandler } from 'hono';

import type { AppEnv, RouteSecurity } from '../contracts';

const continueRequest: MiddlewareHandler<AppEnv> = async (_context, next) => next();

/** Temporary no-op hooks preserve existing endpoint behaviour until Wave 1. */
export const permissiveRouteSecurity: RouteSecurity = {
    saveBodyLimit: continueRequest,
    protectedIpRateLimit: continueRequest,
    callbackIpRateLimit: continueRequest,
    sessionRateLimit: continueRequest,
};
