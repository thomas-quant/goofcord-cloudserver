import { isIP } from 'node:net';

import type { Context } from 'hono';

import type { AppConfig, RateLimitConfig } from '../config';
import type {
    AppEnv,
    ApplicationSecurity,
    RouteSecurity,
    SecurityService,
} from '../contracts';

const PAYLOAD_TOO_LARGE = 'Payload Too Large';
const BAD_REQUEST = 'Bad Request';
const TOO_MANY_REQUESTS = 'Too Many Requests';
const HTTPS_REQUIRED = 'HTTPS Required';
const INTERNAL_SERVER_ERROR = 'Internal Server Error';

type IpAddress = {
    family: 4 | 6;
    bytes: Uint8Array;
};

type Cidr = IpAddress & { prefixLength: number };

type RateLimitEntry = {
    count: number;
    resetAt: number;
};

export type JsonBodyResult<T> =
    | { ok: true; value: T }
    | { ok: false };

/**
 * Reads JSON without exposing parser details to a response. Route handlers can
 * turn an `{ ok: false }` result into their compatible `400 Bad Request` body.
 */
export async function readJsonBody<T>(context: Context<AppEnv>): Promise<JsonBodyResult<T>> {
    try {
        return { ok: true, value: await context.req.json<T>() };
    } catch {
        return { ok: false };
    }
}

/**
 * Security middleware uses one explicit proxy policy: the direct peer must be
 * in TRUSTED_PROXY_CIDRS and it may supply exactly one X-Forwarded-For address
 * plus one X-Forwarded-Proto value. Comma-separated proxy chains are ignored.
 */
export function createSecurity(config: AppConfig): SecurityService {
    const trustedProxyCidrs = config.trustedProxyCidrs
        .map(parseCidr)
        .filter((cidr): cidr is Cidr => cidr !== null);

    const ipLimiter = new InMemoryRateLimiter(config.ipRateLimit, config.rateLimitMaxKeys);
    const callbackLimiter = new InMemoryRateLimiter(config.callbackRateLimit, config.rateLimitMaxKeys);
    const sessionLimiter = new InMemoryRateLimiter(config.sessionRateLimit, config.rateLimitMaxKeys);

    const resolveClientRequest: ApplicationSecurity['resolveClientRequest'] = async (context, next) => {
        const directPeerAddress = normalizeIp(context.env.directPeerAddress);
        const directPeer = directPeerAddress ? parseIp(directPeerAddress) : null;
        const trustedProxy = directPeer !== null && trustedProxyCidrs.some((cidr) => matchesCidr(directPeer, cidr));

        const forwardedIp = trustedProxy ? forwardedSingleIp(context.req.header('x-forwarded-for')) : undefined;
        const ip = forwardedIp ?? directPeerAddress ?? 'unknown';
        const isSecure = trustedProxy
            ? forwardedProtoIsHttps(context.req.header('x-forwarded-proto'))
            : requestIsSecure(context.req.url);

        context.set('clientRequest', {
            ip,
            isSecure,
            // Local HTTP is a direct-development escape hatch only. A proxy's
            // forwarded client address is never authority to bypass HTTPS.
            isLocal: !trustedProxy && directPeerAddress !== null && isLoopback(directPeerAddress),
            directPeerAddress: directPeerAddress ?? undefined,
            trustedProxy,
        });

        await next();
    };

    const enforceHttps: ApplicationSecurity['enforceHttps'] = async (context, next) => {
        const request = context.get('clientRequest');
        if (config.enforceHttps && !request.isSecure && !request.isLocal) {
            applyBaseSecurityHeaders(context);
            return context.json({ error: HTTPS_REQUIRED }, 400);
        }
        await next();
    };

    const securityHeaders: ApplicationSecurity['securityHeaders'] = async (context, next) => {
        applyBaseSecurityHeaders(context);

        if (context.get('clientRequest').isSecure) {
            context.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        await next();
    };

    const onError: ApplicationSecurity['onError'] = (error, context) => {
        if (error instanceof SyntaxError) {
            return context.json({ error: BAD_REQUEST }, 400);
        }

        const status = expectedHttpStatus(error);
        if (status === 400) return context.json({ error: BAD_REQUEST }, 400);
        if (status === 401) return context.json({ error: 'Unauthorized' }, 401);
        if (status === 413) return context.json({ error: PAYLOAD_TOO_LARGE }, 413);
        if (status === 429) return context.json({ error: TOO_MANY_REQUESTS }, 429);

        return context.json({ error: INTERNAL_SERVER_ERROR }, 500);
    };

    const saveBodyLimit: RouteSecurity['saveBodyLimit'] = async (context, next) => {
        const rawRequest = context.req.raw;
        const declaredLength = contentLength(rawRequest.headers.get('content-length'));
        if (declaredLength !== null && declaredLength > config.maxRequestBodyBytes) {
            return context.json({ error: PAYLOAD_TOO_LARGE }, 413);
        }

        if (!rawRequest.body) return next();

        const body = await readBodyWithinLimit(rawRequest.body, config.maxRequestBodyBytes);
        if (body === null) return context.json({ error: PAYLOAD_TOO_LARGE }, 413);

        // The body is checked before authentication and replaces the original
        // request so later c.req.json() calls see the exact validated bytes.
        context.req.raw = new Request(rawRequest, { body });
        await next();
    };

    const protectedIpRateLimit: RouteSecurity['protectedIpRateLimit'] = async (context, next) => {
        const limited = ipLimiter.limit(context.get('clientRequest').ip);
        if (limited !== null) return rateLimitResponse(context, limited);
        await next();
    };

    const callbackIpRateLimit: RouteSecurity['callbackIpRateLimit'] = async (context, next) => {
        const limited = callbackLimiter.limit(context.get('clientRequest').ip);
        if (limited !== null) return rateLimitResponse(context, limited);
        await next();
    };

    const sessionRateLimit: RouteSecurity['sessionRateLimit'] = async (context, next) => {
        // Authentication owns this hash; raw Authorization values are never keys.
        const limited = sessionLimiter.limit(context.get('authenticatedSession').tokenHash);
        if (limited !== null) return rateLimitResponse(context, limited);
        await next();
    };

    return {
        application: {
            resolveClientRequest,
            enforceHttps,
            securityHeaders,
            onError,
        },
        routes: {
            saveBodyLimit,
            protectedIpRateLimit,
            callbackIpRateLimit,
            sessionRateLimit,
        },
    };
}

class InMemoryRateLimiter {
    private readonly entries = new Map<string, RateLimitEntry>();

    constructor(
        private readonly config: RateLimitConfig,
        private readonly maxKeys: number,
    ) {}

    /** Returns milliseconds until retry, or null when the request is allowed. */
    limit(key: string): number | null {
        const now = Date.now();
        this.removeExpired(now);

        const existing = this.entries.get(key);
        if (existing) {
            if (existing.count >= this.config.limit) return existing.resetAt - now;
            existing.count += 1;
            return null;
        }

        if (this.entries.size >= this.maxKeys) {
            return this.earliestResetAt() - now;
        }

        this.entries.set(key, { count: 1, resetAt: now + this.config.windowMs });
        return null;
    }

    private removeExpired(now: number): void {
        for (const [key, entry] of this.entries) {
            if (entry.resetAt <= now) this.entries.delete(key);
        }
    }

    private earliestResetAt(): number {
        let earliest = Number.POSITIVE_INFINITY;
        for (const entry of this.entries.values()) earliest = Math.min(earliest, entry.resetAt);
        return Number.isFinite(earliest) ? earliest : Date.now() + this.config.windowMs;
    }
}

function rateLimitResponse(context: Context<AppEnv>, retryInMs: number): Response {
    context.header('Retry-After', String(Math.max(1, Math.ceil(Math.max(0, retryInMs) / 1_000))));
    return context.json({ error: TOO_MANY_REQUESTS }, 429);
}

function applyBaseSecurityHeaders(context: Context<AppEnv>): void {
    context.header('Cache-Control', 'no-store');
    context.header('Pragma', 'no-cache');
    context.header('Referrer-Policy', 'no-referrer');
    context.header('X-Content-Type-Options', 'nosniff');
    context.header('X-Frame-Options', 'DENY');
}

function contentLength(value: string | null): number | null {
    if (value === null || !/^[0-9]+$/.test(value.trim())) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
}

async function readBodyWithinLimit(
    stream: ReadableStream<Uint8Array>,
    maximumBytes: number,
): Promise<Uint8Array | null> {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;

            totalBytes += value.byteLength;
            if (totalBytes > maximumBytes) {
                await reader.cancel();
                return null;
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    const body = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return body;
}

function normalizeIp(value: string | undefined): string | null {
    if (!value) return null;
    const address = value.trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
    if (!isIP(address)) return null;

    const mappedIpv4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    return mappedIpv4 ? mappedIpv4[1] : address;
}

function forwardedSingleIp(value: string | undefined): string | undefined {
    if (!value || value.includes(',')) return undefined;
    return normalizeIp(value) ?? undefined;
}

function forwardedProtoIsHttps(value: string | undefined): boolean {
    return value?.trim().toLowerCase() === 'https';
}

function requestIsSecure(url: string): boolean {
    try {
        return new URL(url).protocol === 'https:';
    } catch {
        return false;
    }
}

function isLoopback(address: string): boolean {
    const parsed = parseIp(address);
    if (!parsed) return false;
    if (parsed.family === 4) return parsed.bytes[0] === 127;
    return parsed.bytes.every((byte, index) => index === 15 ? byte === 1 : byte === 0);
}

function parseCidr(value: string): Cidr | null {
    const [address, rawPrefix] = value.split('/');
    const ip = parseIp(address);
    if (!ip) return null;
    const prefixLength = rawPrefix === undefined ? ip.bytes.length * 8 : Number(rawPrefix);
    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > ip.bytes.length * 8) return null;
    return { ...ip, prefixLength };
}

function parseIp(value: string): IpAddress | null {
    const family = isIP(value);
    if (family === 4) {
        const bytes = value.split('.').map(Number);
        return { family: 4, bytes: new Uint8Array(bytes) };
    }
    if (family !== 6) return null;

    const bytes = parseIpv6(value);
    return bytes ? { family: 6, bytes } : null;
}

function parseIpv6(value: string): Uint8Array | null {
    const address = value.toLowerCase();
    const doubleColon = address.indexOf('::');
    if (doubleColon !== -1 && doubleColon !== address.lastIndexOf('::')) return null;

    const [leftText, rightText] = doubleColon === -1
        ? [address, '']
        : [address.slice(0, doubleColon), address.slice(doubleColon + 2)];
    const left = leftText ? leftText.split(':') : [];
    const right = rightText ? rightText.split(':') : [];
    const expandIpv4 = (parts: string[]): boolean => {
        const last = parts.at(-1);
        if (!last?.includes('.')) return true;
        const ipv4 = parseIp(last);
        if (!ipv4 || ipv4.family !== 4) return false;
        parts.splice(
            -1,
            1,
            ((ipv4.bytes[0] << 8) | ipv4.bytes[1]).toString(16),
            ((ipv4.bytes[2] << 8) | ipv4.bytes[3]).toString(16),
        );
        return true;
    };

    if (!expandIpv4(left) || !expandIpv4(right)) return null;
    const groups = doubleColon === -1
        ? left
        : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
    if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;

    const bytes = new Uint8Array(16);
    groups.forEach((group, index) => {
        const number = Number.parseInt(group, 16);
        bytes[index * 2] = number >>> 8;
        bytes[index * 2 + 1] = number & 0xff;
    });
    return bytes;
}

function matchesCidr(address: IpAddress, cidr: Cidr): boolean {
    if (address.family !== cidr.family) return false;
    const fullBytes = Math.floor(cidr.prefixLength / 8);
    for (let index = 0; index < fullBytes; index += 1) {
        if (address.bytes[index] !== cidr.bytes[index]) return false;
    }

    const remainingBits = cidr.prefixLength % 8;
    if (!remainingBits) return true;
    const mask = (0xff << (8 - remainingBits)) & 0xff;
    return (address.bytes[fullBytes] & mask) === (cidr.bytes[fullBytes] & mask);
}

function expectedHttpStatus(error: unknown): number | null {
    if (!error || typeof error !== 'object' || !('status' in error)) return null;
    const status = (error as { status?: unknown }).status;
    return typeof status === 'number' ? status : null;
}
