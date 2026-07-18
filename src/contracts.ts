import type { ErrorHandler, MiddlewareHandler } from 'hono';

export interface AuthenticatedSession {
    userId: string;
    tokenHash: string;
}

export interface ResolvedClientRequest {
    ip: string;
    isSecure: boolean;
    isLocal: boolean;
    directPeerAddress: string | undefined;
    trustedProxy: boolean;
}

export type AppVariables = {
    authenticatedSession: AuthenticatedSession;
    clientRequest: ResolvedClientRequest;
};

export type AppEnv = {
    Bindings: { directPeerAddress?: string };
    Variables: AppVariables;
};

export interface AuthenticationService {
    authenticate(rawAuthorization: string): Promise<AuthenticatedSession | null>;
    authenticateReadOnly(rawAuthorization: string): Promise<AuthenticatedSession | null>;
    createSession(userId: string): Promise<string>;
    revokeAllSessions(userId: string): Promise<void>;
}

export interface SettingsService {
    save(userId: string, settings: string): Promise<void>;
    load(userId: string): Promise<string | null>;
    deleteForUser(userId: string): Promise<void>;
}

export type OAuthCodeResult =
    | { kind: 'success'; userId: string }
    | { kind: 'invalid_code' };

export interface OAuthService {
    authorizationUrl(): string;
    userIdForCode(code: string): Promise<OAuthCodeResult>;
}

export interface RouteSecurity {
    saveBodyLimit: MiddlewareHandler<AppEnv>;
    protectedIpRateLimit: MiddlewareHandler<AppEnv>;
    callbackIpRateLimit: MiddlewareHandler<AppEnv>;
    sessionRateLimit: MiddlewareHandler<AppEnv>;
    kdfBodyLimit: MiddlewareHandler<AppEnv>;
    kdfIpRateLimit: MiddlewareHandler<AppEnv>;
    kdfDeriveSessionRateLimit: MiddlewareHandler<AppEnv>;
    kdfRevisionSessionRateLimit: MiddlewareHandler<AppEnv>;
}

export interface ApplicationSecurity {
    resolveClientRequest: MiddlewareHandler<AppEnv>;
    enforceHttps: MiddlewareHandler<AppEnv>;
    securityHeaders: MiddlewareHandler<AppEnv>;
    onError: ErrorHandler<AppEnv>;
}

export interface SecurityService {
    application: ApplicationSecurity;
    routes: RouteSecurity;
}

export interface V1Dependencies {
    clientId: string;
    auth: AuthenticationService;
    settings: SettingsService;
    oauth: OAuthService;
    security: RouteSecurity;
}
