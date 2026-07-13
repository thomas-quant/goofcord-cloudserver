import { isIP } from 'node:net';

export interface RateLimitConfig {
    limit: number;
    windowMs: number;
}

export interface AppConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    mongoUri: string;
    port: number;
    mongoServerSelectionTimeoutMs: number;
    maxRequestBodyBytes: number;
    sessionTouchIntervalMs: number;
    enforceHttps: boolean;
    trustedProxyCidrs: string[];
    rateLimitMaxKeys: number;
    ipRateLimit: RateLimitConfig;
    callbackRateLimit: RateLimitConfig;
    sessionRateLimit: RateLimitConfig;
}

type Environment = Record<string, string | undefined>;

const REQUIRED_VARIABLES = ['CLIENT_ID', 'CLIENT_SECRET', 'REDIRECT_URI', 'MONGO_URI'] as const;
const ONE_MEBIBYTE = 1024 * 1024;

function required(environment: Environment, name: typeof REQUIRED_VARIABLES[number]): string {
    const value = environment[name]?.trim();
    if (!value) throw new Error(`Missing required environment variable: ${name}`);
    return value;
}

function integer(
    environment: Environment,
    name: string,
    fallback: number,
    minimum: number,
    maximum: number,
): number {
    const raw = environment[name];
    if (raw === undefined || raw === '') return fallback;

    if (!/^[0-9]+$/.test(raw)) {
        throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
    }

    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
    }

    return value;
}

function boolean(environment: Environment, name: string, fallback: boolean): boolean {
    const raw = environment[name];
    if (raw === undefined || raw === '') return fallback;
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    throw new Error(`${name} must be either true or false`);
}

function redirectUri(environment: Environment): string {
    const value = required(environment, 'REDIRECT_URI');
    let parsed: URL;
    try {
        parsed = new URL(value);
    } catch {
        throw new Error('REDIRECT_URI must be an absolute HTTP(S) base URL');
    }

    if (
        !['http:', 'https:'].includes(parsed.protocol)
        || parsed.pathname !== '/'
        || parsed.search
        || parsed.hash
    ) {
        throw new Error('REDIRECT_URI must be an HTTP(S) base URL without a path, query, or fragment');
    }

    return parsed.origin;
}

function trustedProxyCidrs(environment: Environment): string[] {
    return (environment.TRUSTED_PROXY_CIDRS ?? '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
        .map((value) => {
            const [address, prefix, ...extra] = value.split('/');
            const family = isIP(address);
            const maximumPrefix = family === 4 ? 32 : 128;
            if (!family || extra.length > 0 || (prefix !== undefined && (!/^[0-9]+$/.test(prefix) || Number(prefix) > maximumPrefix))) {
                throw new Error(`TRUSTED_PROXY_CIDRS contains an invalid IP address or CIDR: ${value}`);
            }
            return value;
        });
}

function rateLimit(environment: Environment, prefix: string, fallback: RateLimitConfig): RateLimitConfig {
    return {
        limit: integer(environment, `${prefix}_LIMIT`, fallback.limit, 1, 1_000_000),
        windowMs: integer(environment, `${prefix}_WINDOW_MS`, fallback.windowMs, 1_000, 86_400_000),
    };
}

/** Parse all runtime settings before the server attempts to connect or listen. */
export function loadConfig(environment: Environment = process.env): AppConfig {
    return {
        clientId: required(environment, 'CLIENT_ID'),
        clientSecret: required(environment, 'CLIENT_SECRET'),
        redirectUri: redirectUri(environment),
        mongoUri: required(environment, 'MONGO_URI'),
        port: integer(environment, 'PORT', 3000, 1, 65_535),
        mongoServerSelectionTimeoutMs: integer(
            environment,
            'MONGO_SERVER_SELECTION_TIMEOUT_MS',
            5_000,
            100,
            120_000,
        ),
        maxRequestBodyBytes: integer(environment, 'MAX_REQUEST_BODY_BYTES', ONE_MEBIBYTE, 1, 100 * ONE_MEBIBYTE),
        sessionTouchIntervalMs: integer(
            environment,
            'SESSION_TOUCH_INTERVAL_MS',
            15 * 60 * 1_000,
            1_000,
            24 * 60 * 60 * 1_000,
        ),
        enforceHttps: boolean(environment, 'ENFORCE_HTTPS', false),
        trustedProxyCidrs: trustedProxyCidrs(environment),
        rateLimitMaxKeys: integer(environment, 'RATE_LIMIT_MAX_KEYS', 10_000, 100, 1_000_000),
        ipRateLimit: rateLimit(environment, 'IP_RATE', { limit: 120, windowMs: 60_000 }),
        callbackRateLimit: rateLimit(environment, 'CALLBACK_RATE', { limit: 20, windowMs: 60_000 }),
        sessionRateLimit: rateLimit(environment, 'SESSION_RATE', { limit: 60, windowMs: 60_000 }),
    };
}
