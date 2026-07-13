import { describe, expect, test } from 'bun:test';

import { loadConfig } from '../src/config';
import { validEnvironment } from './helpers/environment';

describe('loadConfig', () => {
    test('uses safe hardening defaults', () => {
        const config = loadConfig(validEnvironment());

        expect(config.port).toBe(3000);
        expect(config.maxRequestBodyBytes).toBe(1024 * 1024);
        expect(config.sessionTouchIntervalMs).toBe(15 * 60 * 1_000);
        expect(config.mongoServerSelectionTimeoutMs).toBe(5_000);
        expect(config.enforceHttps).toBe(false);
    });

    test('rejects missing required settings and invalid ports', () => {
        const missing = validEnvironment();
        delete missing.CLIENT_SECRET;
        expect(() => loadConfig(missing)).toThrow('CLIENT_SECRET');

        expect(() => loadConfig({ ...validEnvironment(), PORT: 'not-a-port' })).toThrow('PORT');
        expect(() => loadConfig({ ...validEnvironment(), PORT: '65536' })).toThrow('PORT');
    });

    test('parses validated overrides', () => {
        const config = loadConfig({
            ...validEnvironment(),
            PORT: '8443',
            ENFORCE_HTTPS: 'true',
            TRUSTED_PROXY_CIDRS: '127.0.0.1, 10.0.0.0/8 ',
            IP_RATE_LIMIT: '10',
            IP_RATE_WINDOW_MS: '2000',
        });

        expect(config.port).toBe(8443);
        expect(config.enforceHttps).toBe(true);
        expect(config.trustedProxyCidrs).toEqual(['127.0.0.1', '10.0.0.0/8']);
        expect(config.ipRateLimit).toEqual({ limit: 10, windowMs: 2000 });
    });

    test('requires a base redirect URL and valid proxy addresses', () => {
        expect(() => loadConfig({ ...validEnvironment(), REDIRECT_URI: 'http://localhost:3000/v1/callback' }))
            .toThrow('REDIRECT_URI');
        expect(() => loadConfig({ ...validEnvironment(), TRUSTED_PROXY_CIDRS: 'not-an-address' }))
            .toThrow('TRUSTED_PROXY_CIDRS');
    });
});
