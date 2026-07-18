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
        expect(config.kdfGlobalConcurrency).toBe(1);
        expect(config.kdfJobTimeoutMs).toBe(30_000);
        expect(config.kdfAllowInsecureLocalhost).toBe(false);
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
            KDF_GLOBAL_CONCURRENCY: '4',
            KDF_JOB_TIMEOUT_MS: '120000',
            KDF_ALLOW_INSECURE_LOCALHOST: 'true',
        });

        expect(config.port).toBe(8443);
        expect(config.enforceHttps).toBe(true);
        expect(config.trustedProxyCidrs).toEqual(['127.0.0.1', '10.0.0.0/8']);
        expect(config.ipRateLimit).toEqual({ limit: 10, windowMs: 2000 });
        expect(config.kdfGlobalConcurrency).toBe(4);
        expect(config.kdfJobTimeoutMs).toBe(120_000);
        expect(config.kdfAllowInsecureLocalhost).toBe(true);
    });

    test('requires a base redirect URL and valid proxy addresses', () => {
        expect(() => loadConfig({ ...validEnvironment(), REDIRECT_URI: 'http://localhost:3000/v1/callback' }))
            .toThrow('REDIRECT_URI');
        expect(() => loadConfig({ ...validEnvironment(), TRUSTED_PROXY_CIDRS: 'not-an-address' }))
            .toThrow('TRUSTED_PROXY_CIDRS');
    });

    test('enforces exact KDF worker and timeout ranges', () => {
        expect(loadConfig({
            ...validEnvironment(),
            KDF_GLOBAL_CONCURRENCY: '1',
            KDF_JOB_TIMEOUT_MS: '5000',
        })).toMatchObject({ kdfGlobalConcurrency: 1, kdfJobTimeoutMs: 5000 });

        for (const value of ['0', '5', 'not-an-integer']) {
            expect(() => loadConfig({ ...validEnvironment(), KDF_GLOBAL_CONCURRENCY: value }))
                .toThrow('KDF_GLOBAL_CONCURRENCY');
        }
        for (const value of ['4999', '120001', 'not-an-integer']) {
            expect(() => loadConfig({ ...validEnvironment(), KDF_JOB_TIMEOUT_MS: value }))
                .toThrow('KDF_JOB_TIMEOUT_MS');
        }
        expect(() => loadConfig({ ...validEnvironment(), KDF_ALLOW_INSECURE_LOCALHOST: 'yes' }))
            .toThrow('KDF_ALLOW_INSECURE_LOCALHOST');
    });
});
