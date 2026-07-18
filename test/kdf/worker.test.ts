import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

interface ArgonVector {
    password: string;
    channelId: string;
    keyHex: string;
    keyBase64: string;
}

const vector = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/argon2id-v1.json', import.meta.url),
    'utf8',
)) as ArgonVector;

function exchange(worker: Worker, message: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            worker.onmessage = null;
            worker.onerror = null;
            reject(new Error('worker response timeout'));
        }, 30_000);
        worker.onmessage = (event) => {
            clearTimeout(timeout);
            worker.onmessage = null;
            worker.onerror = null;
            resolve(event.data);
        };
        worker.onerror = () => {
            clearTimeout(timeout);
            worker.onmessage = null;
            worker.onerror = null;
            reject(new Error('worker failed'));
        };
        worker.postMessage(message);
    });
}

describe('remote KDF worker engine', () => {
    test('passes its startup vector, derives exact bytes off the primary loop, and fails generically', async () => {
        const worker = new Worker(new URL('../../src/kdf/worker.ts', import.meta.url));
        try {
            const selfTest = await exchange(worker, {
                version: 1,
                type: 'self-test',
                requestId: 'startup-vector',
            });
            expect(selfTest).toEqual({
                version: 1,
                type: 'self-test',
                requestId: 'startup-vector',
                ok: true,
            });

            let primaryLoopTicks = 0;
            const interval = setInterval(() => {
                primaryLoopTicks += 1;
            }, 1);
            let response: unknown;
            try {
                response = await exchange(worker, {
                    version: 1,
                    type: 'derive',
                    requestId: 'exact-vector',
                    password: vector.password,
                    channelId: vector.channelId,
                });
            } finally {
                clearInterval(interval);
            }

            expect(primaryLoopTicks).toBeGreaterThan(0);
            expect(response).toEqual({
                version: 1,
                type: 'derive',
                requestId: 'exact-vector',
                ok: true,
                key: vector.keyBase64,
            });
            expect(Buffer.from((response as { key: string }).key, 'base64').toString('hex')).toBe(vector.keyHex);

            const secretMarker = 'must-not-be-reflected';
            const malformed = await exchange(worker, {
                version: 1,
                type: 'derive',
                requestId: secretMarker,
                password: secretMarker,
                channelId: 'not-a-channel',
                extra: secretMarker,
            });
            expect(malformed).toEqual({
                version: 1,
                type: 'error',
                ok: false,
                error: 'KDF_WORKER_FAILED',
            });
            expect(JSON.stringify(malformed)).not.toContain(secretMarker);

            const workerSource = readFileSync(new URL('../../src/kdf/worker.ts', import.meta.url), 'utf8');
            expect(workerSource).not.toContain('console.');
        } finally {
            worker.terminate();
        }
    }, 90_000);
});
