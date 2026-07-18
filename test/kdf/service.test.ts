import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import type { DecodedCloudBlob } from '../../src/kdf/cloudBlob';
import {
    createKdfWorkerPool,
    type KdfBatchLease,
    type KdfWorkerPool,
} from '../../src/kdf/pool';
import { createRemoteKdfService } from '../../src/kdf/service';

interface CloudFixtures {
    encrypted: { cloudEncryptionKey: string; blob: string };
    wrongKey: { cloudEncryptionKey: string; blob: string };
}

const fixtures = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/cloud-blobs-v1.json', import.meta.url),
    'utf8',
)) as CloudFixtures;
const VECTOR_KEY = 'WNRTGTkvrju+EwmAg1mCEem36E040hCwFKVkROLN6AQ=';

class FakePool implements KdfWorkerPool {
    initialized = 0;
    closed = 0;
    deriveCalls: Array<{ password: string; channelId: string }> = [];
    available = true;
    blocker: Promise<void> | undefined;
    private leased = false;

    async initialize(): Promise<void> {
        this.initialized += 1;
    }

    tryAcquire(): KdfBatchLease {
        if (!this.available || this.leased) throw Object.assign(new Error('KDF_BUSY'), { code: 'KDF_BUSY' });
        this.leased = true;
        let released = false;
        return {
            derive: async (password, channelId) => {
                this.deriveCalls.push({ password, channelId });
                await this.blocker;
                return VECTOR_KEY;
            },
            release: () => {
                if (released) return;
                released = true;
                this.leased = false;
            },
        };
    }

    async close(): Promise<void> {
        this.closed += 1;
    }
}

describe('remote KDF service', () => {
    test('delegates lifecycle and revision without decoding or acquiring a worker', async () => {
        const pool = new FakePool();
        let decoded = 0;
        const service = createRemoteKdfService(pool, async () => {
            decoded += 1;
            throw new Error('must not decode');
        });
        await service.initialize();
        const revision = service.revision(fixtures.encrypted.blob);
        await service.close();

        expect(pool.initialized).toBe(1);
        expect(pool.closed).toBe(1);
        expect(decoded).toBe(0);
        expect(revision.settingsRevision).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(pool.deriveCalls).toHaveLength(0);
    });

    test('rejects same-account and global overlap immediately', async () => {
        const pool = new FakePool();
        let release!: () => void;
        pool.blocker = new Promise<void>((resolve) => {
            release = resolve;
        });
        const service = createRemoteKdfService(pool, async () => ({
            passwords: ['one'],
            settingsRevision: 'A'.repeat(43),
        }));

        const first = service.derive('account-a', 'blob', 'cloud', '1');
        await Promise.resolve();
        await expect(service.derive('account-a', 'blob', 'cloud', '2'))
            .rejects.toMatchObject({ code: 'KDF_BUSY' });
        await expect(service.derive('account-b', 'blob', 'cloud', '2'))
            .rejects.toMatchObject({ code: 'KDF_BUSY' });
        release();
        await first;
    });

    test('decodes before worker derives, preserves sequential slot order, and clears passwords', async () => {
        const pool = new FakePool();
        let inFlight = 0;
        let maximumInFlight = 0;
        const passwords = ['first', '  café 🔐  ', 'third'];
        pool.tryAcquire = () => {
            let released = false;
            return {
                derive: async (password, channelId) => {
                    inFlight += 1;
                    maximumInFlight = Math.max(maximumInFlight, inFlight);
                    await Promise.resolve();
                    pool.deriveCalls.push({ password, channelId });
                    inFlight -= 1;
                    return VECTOR_KEY;
                },
                release: () => {
                    released = true;
                },
            };
        };
        const decoder = async (): Promise<DecodedCloudBlob> => ({
            passwords,
            settingsRevision: 'B'.repeat(43),
        });
        const service = createRemoteKdfService(pool, decoder);

        const response = await service.derive('account', 'blob', 'cloud', '123');
        expect(maximumInFlight).toBe(1);
        expect(pool.deriveCalls).toEqual([
            { password: 'first', channelId: '123' },
            { password: '  café 🔐  ', channelId: '123' },
            { password: 'third', channelId: '123' },
        ]);
        expect(response).toEqual({
            version: 1,
            settingsRevision: 'B'.repeat(43),
            keys: [
                { slot: 0, key: VECTOR_KEY },
                { slot: 1, key: VECTOR_KEY },
                { slot: 2, key: VECTOR_KEY },
            ],
        });
        expect(passwords).toEqual(['', '', '']);
    });

    test('wrong cloud key causes zero worker derive calls and releases admission', async () => {
        const pool = new FakePool();
        const service = createRemoteKdfService(pool);
        await expect(service.derive(
            'account',
            fixtures.wrongKey.blob,
            fixtures.wrongKey.cloudEncryptionKey,
            '1',
        )).rejects.toMatchObject({ code: 'CLOUD_DECRYPT_FAILED' });
        expect(pool.deriveCalls).toHaveLength(0);

        await expect(service.derive(
            'account',
            fixtures.wrongKey.blob,
            fixtures.wrongKey.cloudEncryptionKey,
            '1',
        )).rejects.toMatchObject({ code: 'CLOUD_DECRYPT_FAILED' });
    });

    test('re-derives identical requests instead of caching server keys', async () => {
        const pool = new FakePool();
        const service = createRemoteKdfService(pool, async () => ({
            passwords: ['one', 'two'],
            settingsRevision: 'C'.repeat(43),
        }));
        await service.derive('account', 'blob', 'cloud', '1');
        await service.derive('account', 'blob', 'cloud', '1');
        expect(pool.deriveCalls).toHaveLength(4);
    });

    test('returns the exact Stage 1 vector through the real decoder and worker pool', async () => {
        const pool = createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 30000 });
        const service = createRemoteKdfService(pool);
        await service.initialize();
        try {
            const response = await service.derive(
                'public-account',
                fixtures.encrypted.blob,
                fixtures.encrypted.cloudEncryptionKey,
                '1234567890123456789',
            );
            expect(response.keys).toHaveLength(2);
            expect(response.keys[0]).toEqual({ slot: 0, key: VECTOR_KEY });
            expect(response.keys.map((entry) => entry.slot)).toEqual([0, 1]);
        } finally {
            await service.close();
        }
    }, 90_000);
});
