import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import {
    createKdfWorkerPool,
    type KdfWorkerPort,
    type PoolClock,
} from '../../src/kdf/pool';

interface ArgonFixture {
    password: string;
    channelId: string;
    keyBase64: string;
}

const vector = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/argon2id-v1.json', import.meta.url),
    'utf8',
)) as ArgonFixture;

type Request = Record<string, unknown>;

class FakeWorker implements KdfWorkerPort {
    onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
    onerror: ((event: ErrorEvent) => void) | null = null;
    onclose: (() => void) | null = null;
    readonly messages: Request[] = [];
    terminated = false;

    constructor(private readonly respond: (worker: FakeWorker, request: Request) => void) {}

    postMessage(message: unknown): void {
        const request = message as Request;
        this.messages.push(request);
        this.respond(this, request);
    }

    terminate(): void {
        this.terminated = true;
    }

    emit(data: unknown): void {
        queueMicrotask(() => this.onmessage?.({ data } as MessageEvent<unknown>));
    }
}

function successResponder(worker: FakeWorker, request: Request): void {
    if (request.type === 'self-test') {
        worker.emit({ version: 1, type: 'self-test', requestId: request.requestId, ok: true });
        return;
    }
    worker.emit({
        version: 1,
        type: 'derive',
        requestId: request.requestId,
        ok: true,
        key: vector.keyBase64,
    });
}

const immediateTimeoutClock: PoolClock = {
    schedule(callback, milliseconds) {
        expect(milliseconds).toBe(5000);
        queueMicrotask(callback);
        return 1;
    },
    cancel() {},
};

async function settle(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('bounded KDF worker pool', () => {
    test('validates frozen capacity and timeout ranges', () => {
        expect(() => createKdfWorkerPool({ capacity: 0, jobTimeoutMs: 30000 })).toThrow();
        expect(() => createKdfWorkerPool({ capacity: 5, jobTimeoutMs: 30000 })).toThrow();
        expect(() => createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 4999 })).toThrow();
        expect(() => createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 120001 })).toThrow();
        expect(() => createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 5000 })).not.toThrow();
        expect(() => createKdfWorkerPool({ capacity: 4, jobTimeoutMs: 120000 })).not.toThrow();
    });

    test('self-tests every configured worker before admitting leases', async () => {
        const workers: FakeWorker[] = [];
        const pool = createKdfWorkerPool({
            capacity: 2,
            jobTimeoutMs: 30000,
            workerFactory: () => {
                const worker = new FakeWorker(successResponder);
                workers.push(worker);
                return worker;
            },
        });

        await pool.initialize();
        expect(workers).toHaveLength(2);
        expect(workers.map((worker) => worker.messages[0]?.type)).toEqual(['self-test', 'self-test']);

        const first = pool.tryAcquire();
        const second = pool.tryAcquire();
        expect(() => pool.tryAcquire()).toThrow(expect.objectContaining({ code: 'KDF_BUSY' }));
        first.release();
        second.release();
        await pool.close();
    });

    test('derives the committed exact vector through a real Stage 1 worker', async () => {
        const pool = createKdfWorkerPool({ capacity: 1, jobTimeoutMs: 30000 });
        await pool.initialize();
        const lease = pool.tryAcquire();
        try {
            expect(await lease.derive(vector.password, vector.channelId))
                .toBe(vector.keyBase64);
        } finally {
            lease.release();
            await pool.close();
        }
    });

    test('fails startup generically and terminates every worker when any self-test fails', async () => {
        const workers: FakeWorker[] = [];
        let created = 0;
        const pool = createKdfWorkerPool({
            capacity: 2,
            jobTimeoutMs: 30000,
            workerFactory: () => {
                created += 1;
                const worker = new FakeWorker((current, request) => {
                    if (created === 2) {
                        current.emit({ version: 1, type: 'error', ok: false, error: 'KDF_WORKER_FAILED' });
                    } else {
                        successResponder(current, request);
                    }
                });
                workers.push(worker);
                return worker;
            },
        });

        await expect(pool.initialize()).rejects.toMatchObject({ code: 'KDF_FAILED' });
        expect(workers.every((worker) => worker.terminated)).toBe(true);
    });

    test('quarantines a timed-out slot and admits one self-tested replacement', async () => {
        const workers: FakeWorker[] = [];
        const pool = createKdfWorkerPool({
            capacity: 1,
            jobTimeoutMs: 5000,
            clock: immediateTimeoutClock,
            workerFactory: () => {
                const worker = new FakeWorker(workers.length === 0
                    ? (current, request) => {
                        if (request.type === 'self-test') successResponder(current, request);
                    }
                    : successResponder);
                workers.push(worker);
                return worker;
            },
        });
        await pool.initialize();
        const lease = pool.tryAcquire();
        await expect(lease.derive('public synthetic password', '1'))
            .rejects.toMatchObject({ code: 'KDF_FAILED' });
        lease.release();
        await settle();

        expect(workers).toHaveLength(2);
        expect(workers[0].terminated).toBe(true);
        expect(workers[1].messages[0]?.type).toBe('self-test');
        const replacementLease = pool.tryAcquire();
        replacementLease.release();
        await pool.close();
    });

    test('attempts a failed replacement once and returns busy without a healthy slot', async () => {
        let created = 0;
        const pool = createKdfWorkerPool({
            capacity: 1,
            jobTimeoutMs: 5000,
            clock: immediateTimeoutClock,
            workerFactory: () => {
                created += 1;
                return new FakeWorker((worker, request) => {
                    if (created === 1 && request.type === 'self-test') successResponder(worker, request);
                    if (created === 2) {
                        worker.emit({ version: 1, type: 'error', ok: false, error: 'KDF_WORKER_FAILED' });
                    }
                });
            },
        });
        await pool.initialize();
        const lease = pool.tryAcquire();
        await expect(lease.derive('public synthetic password', '1'))
            .rejects.toMatchObject({ code: 'KDF_FAILED' });
        lease.release();
        await settle();
        await settle();

        expect(created).toBe(2);
        expect(() => pool.tryAcquire()).toThrow(expect.objectContaining({ code: 'KDF_BUSY' }));
        await pool.close();
        expect(created).toBe(2);
    });

    test('shutdown wins a pending replacement race and is idempotent', async () => {
        let created = 0;
        let replacement: FakeWorker | undefined;
        const pool = createKdfWorkerPool({
            capacity: 1,
            jobTimeoutMs: 5000,
            clock: immediateTimeoutClock,
            workerFactory: () => {
                created += 1;
                const worker = new FakeWorker((current, request) => {
                    if (created === 1 && request.type === 'self-test') successResponder(current, request);
                });
                if (created === 2) replacement = worker;
                return worker;
            },
        });
        await pool.initialize();
        const lease = pool.tryAcquire();
        await expect(lease.derive('public synthetic password', '1'))
            .rejects.toMatchObject({ code: 'KDF_FAILED' });
        lease.release();

        await Promise.all([pool.close(), pool.close()]);
        expect(replacement?.terminated).toBe(true);
        expect(() => pool.tryAcquire()).toThrow(expect.objectContaining({ code: 'KDF_BUSY' }));
    });
});
