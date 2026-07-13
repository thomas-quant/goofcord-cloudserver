import { Hono } from 'hono';

import type {
    AppEnv,
    AuthenticationService,
    OAuthService,
    SecurityService,
    SettingsService,
} from '../contracts';
import { createV1Router } from '../routes/v1';
import v2 from '../routes/v2';

import type { MongoConnectionState, Readiness } from './readiness';
import { isReady } from './readiness';

export interface ApplicationDependencies {
    clientId: string;
    auth: AuthenticationService;
    settings: SettingsService;
    oauth: OAuthService;
    security: SecurityService;
    readiness: Readiness;
    mongoConnection: MongoConnectionState;
}

/** Build the entire application explicitly; route import/registration failures are startup failures. */
export function createApplication(dependencies: ApplicationDependencies): Hono<AppEnv> {
    const app = new Hono<AppEnv>();
    const { application } = dependencies.security;

    // Client identity must be resolved before all consumers of it. Headers run
    // around the rest of the request and the global error handler is last.
    app.use('*', application.resolveClientRequest);
    app.use('*', application.enforceHttps);
    app.use('*', application.securityHeaders);
    app.onError(application.onError);

    // The shared IP limiter is authentication-independent, so health remains
    // probeable without becoming an unbounded unauthenticated endpoint.
    app.get('/healthz', dependencies.security.routes.protectedIpRateLimit, (context) => {
        return isReady(dependencies.readiness, dependencies.mongoConnection)
            ? context.text('OK')
            : context.text('Service Unavailable', 503);
    });

    app.route('/v1', createV1Router({
        clientId: dependencies.clientId,
        auth: dependencies.auth,
        settings: dependencies.settings,
        oauth: dependencies.oauth,
        security: dependencies.security.routes,
    }));
    app.route('/v2', v2);

    app.get('/', (context) => context.redirect('https://codeberg.org/wuemeli/goofcord-cloudserver'));

    return app;
}
