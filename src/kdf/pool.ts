/**
 * Fixed-capacity Bun Worker pool for exact remote Argon2id derivation.
 *
 * There is no request queue. Unhealthy slots are quarantined and receive one
 * self-tested replacement attempt; worker inputs and outputs are never logged.
 */
import { randomUUID } from 'node:crypto';

import { KdfError } from './contracts';

export const MIN_KDF_WORKERS = 1;
export const MAX_KDF_WORKERS = 4;
export const MIN_KDF_JOB_TIMEOUT_MS = 5000;
export const MAX_KDF_JOB_TIMEOUT_MS = 120000;

export interface KdfWorkerPort {
    onmessage: ((event: MessageEvent<unknown>) => void) | null;
    onerror: ((event: ErrorEvent) => void) | null;
    onclose?: (() => void) | null;
    postMessage(message: unknown): void;
    terminate(): unknown;
}

export interface PoolClock {
    schedule(callback: () => void, milliseconds: number): unknown;
    cancel(handle: unknown): void;
}

export interface KdfBatchLease {
    derive(password: string, channelId: string): Promise<string>;
    release(): void;
}

export interface KdfWorkerPool {
    initialize(): Promise<void>;
    tryAcquire(): KdfBatchLease;
    close(): Promise<void>;
}

export interface KdfWorkerPoolOptions {
    capacity: number;
    jobTimeoutMs: number;
    workerFactory?: () => KdfWorkerPort;
    clock?: PoolClock;
}

type WorkerRequestType = 'self-test' | 'derive';
type SlotState = 'initializing' | 'idle' | 'leased' | 'quarantined' | 'replacing' | 'closed';

interface PendingRequest {
    requestId: string;
    type: WorkerRequestType;
    resolve(value: unknown): void;
    reject(error: Error): void;
    timer?: unknown;
}

interface WorkerSlot {
    state: SlotState;
    client?: WorkerClient;
    replacement?: Promise<void>;
}

const KEY_BASE64 = /^[A-Za-z0-9+/]{43}=$/;
const defaultClock: PoolClock = {
    schedule: (callback, milliseconds) => setTimeout(callback, milliseconds),
    cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
    const keys = Object.keys(value);
    return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function validSelfTest(value: unknown, requestId: string): boolean {
    return isRecord(value)
        && hasExactKeys(value, ['version', 'type', 'requestId', 'ok'])
        && value.version === 1
        && value.type === 'self-test'
        && value.requestId === requestId
        && value.ok === true;
}

function validDerivedKey(value: unknown, requestId: string): value is { key: string } {
    if (
        !isRecord(value)
        || !hasExactKeys(value, ['version', 'type', 'requestId', 'ok', 'key'])
        || value.version !== 1
        || value.type !== 'derive'
        || value.requestId !== requestId
        || value.ok !== true
        || typeof value.key !== 'string'
        || !KEY_BASE64.test(value.key)
    ) {
        return false;
    }
    const decoded = Buffer.from(value.key, 'base64');
    try {
        return decoded.length === 32 && decoded.toString('base64') === value.key;
    } finally {
        decoded.fill(0);
    }
}

class WorkerClient {
    private pending: PendingRequest | undefined;
    private closed = false;

    constructor(
        private readonly worker: KdfWorkerPort,
        private readonly timeoutMs: number,
        private readonly clock: PoolClock,
    ) {
        worker.onmessage = (event) => this.receive(event.data);
        worker.onerror = () => this.rejectPending();
        worker.onclose = () => this.rejectPending();
    }

    async selfTest(): Promise<void> {
        const requestId = randomUUID();
        const response = await this.exchange('self-test', requestId, {
            version: 1,
            type: 'self-test',
            requestId,
        });
        if (!validSelfTest(response, requestId)) throw new Error('KDF_WORKER_FAILED');
    }

    async derive(password: string, channelId: string): Promise<string> {
        const requestId = randomUUID();
        const response = await this.exchange('derive', requestId, {
            version: 1,
            type: 'derive',
            requestId,
            password,
            channelId,
        });
        if (!validDerivedKey(response, requestId)) throw new Error('KDF_WORKER_FAILED');
        return response.key;
    }

    async close(): Promise<void> {
        if (this.closed) return;
        this.closed = true;
        this.rejectPending();
        this.worker.onmessage = null;
        this.worker.onerror = null;
        this.worker.onclose = null;
        await Promise.resolve(this.worker.terminate()).catch(() => undefined);
    }

    private exchange(type: WorkerRequestType, requestId: string, message: unknown): Promise<unknown> {
        if (this.closed || this.pending) return Promise.reject(new Error('KDF_WORKER_FAILED'));

        return new Promise((resolve, reject) => {
            const pending: PendingRequest = { requestId, type, resolve, reject };
            this.pending = pending;
            try {
                this.worker.postMessage(message);
            } catch {
                this.rejectPending();
                return;
            }
            if (this.pending === pending) {
                pending.timer = this.clock.schedule(() => this.rejectPending(), this.timeoutMs);
            }
        });
    }

    private receive(value: unknown): void {
        const pending = this.pending;
        if (!pending) return;
        this.pending = undefined;
        if (pending.timer !== undefined) this.clock.cancel(pending.timer);
        pending.resolve(value);
    }

    private rejectPending(): void {
        const pending = this.pending;
        if (!pending) return;
        this.pending = undefined;
        if (pending.timer !== undefined) this.clock.cancel(pending.timer);
        pending.reject(new Error('KDF_WORKER_FAILED'));
    }
}

class BoundedKdfWorkerPool implements KdfWorkerPool {
    private readonly slots: WorkerSlot[];
    private readonly factory: () => KdfWorkerPort;
    private readonly clock: PoolClock;
    private initialized = false;
    private closing = false;
    private closePromise: Promise<void> | undefined;

    constructor(private readonly options: KdfWorkerPoolOptions) {
        if (
            !Number.isSafeInteger(options.capacity)
            || options.capacity < MIN_KDF_WORKERS
            || options.capacity > MAX_KDF_WORKERS
        ) {
            throw new Error('KDF worker capacity is invalid');
        }
        if (
            !Number.isSafeInteger(options.jobTimeoutMs)
            || options.jobTimeoutMs < MIN_KDF_JOB_TIMEOUT_MS
            || options.jobTimeoutMs > MAX_KDF_JOB_TIMEOUT_MS
        ) {
            throw new Error('KDF worker timeout is invalid');
        }

        this.factory = options.workerFactory ?? (() => new Worker(
            new URL('./worker.ts', import.meta.url),
        ) as unknown as KdfWorkerPort);
        this.clock = options.clock ?? defaultClock;
        this.slots = Array.from({ length: options.capacity }, () => ({ state: 'initializing' }));
    }

    async initialize(): Promise<void> {
        if (this.initialized) return;
        if (this.closing) throw new KdfError('KDF_FAILED');
        try {
            await Promise.all(this.slots.map((slot) => this.initializeSlot(slot)));
            if (this.closing) throw new Error('KDF_WORKER_FAILED');
            this.initialized = true;
        } catch {
            await this.close();
            throw new KdfError('KDF_FAILED');
        }
    }

    tryAcquire(): KdfBatchLease {
        const slot = this.slots.find((candidate) => candidate.state === 'idle' && candidate.client);
        if (this.closing || !this.initialized || !slot?.client) throw new KdfError('KDF_BUSY');

        slot.state = 'leased';
        const client = slot.client;
        let released = false;
        return {
            derive: async (password, channelId) => {
                if (released || slot.state !== 'leased' || slot.client !== client) {
                    throw new KdfError('KDF_FAILED');
                }
                try {
                    return await client.derive(password, channelId);
                } catch {
                    this.quarantine(slot, client);
                    throw new KdfError('KDF_FAILED');
                }
            },
            release: () => {
                if (released) return;
                released = true;
                if (!this.closing && slot.state === 'leased' && slot.client === client) {
                    slot.state = 'idle';
                }
            },
        };
    }

    close(): Promise<void> {
        this.closePromise ??= this.closeAll();
        return this.closePromise;
    }

    private async initializeSlot(slot: WorkerSlot): Promise<void> {
        slot.state = 'initializing';
        const client = new WorkerClient(this.factory(), this.options.jobTimeoutMs, this.clock);
        slot.client = client;
        await client.selfTest();
        if (this.closing) {
            await client.close();
            throw new Error('KDF_WORKER_FAILED');
        }
        slot.state = 'idle';
    }

    private quarantine(slot: WorkerSlot, failed: WorkerClient): void {
        if (slot.client !== failed || ['quarantined', 'replacing', 'closed'].includes(slot.state)) return;
        slot.state = 'quarantined';
        slot.client = undefined;

        const replacement = (async () => {
            await failed.close();
            if (this.closing) return;
            slot.state = 'replacing';
            const client = new WorkerClient(this.factory(), this.options.jobTimeoutMs, this.clock);
            slot.client = client;
            await client.selfTest();
            if (this.closing) {
                await client.close();
                slot.client = undefined;
                slot.state = 'closed';
                return;
            }
            slot.state = 'idle';
        })().catch(async () => {
            await slot.client?.close().catch(() => undefined);
            slot.client = undefined;
            if (!this.closing) slot.state = 'quarantined';
        });
        slot.replacement = replacement.finally(() => {
            slot.replacement = undefined;
        });
    }

    private async closeAll(): Promise<void> {
        this.closing = true;
        this.initialized = false;
        const clients = this.slots.map((slot) => slot.client).filter((value): value is WorkerClient => Boolean(value));
        await Promise.all(clients.map((client) => client.close()));
        const replacements = this.slots.map((slot) => slot.replacement)
            .filter((value): value is Promise<void> => Boolean(value));
        await Promise.all(replacements);
        await Promise.all(this.slots.map((slot) => slot.client?.close()));
        for (const slot of this.slots) {
            slot.client = undefined;
            slot.replacement = undefined;
            slot.state = 'closed';
        }
    }
}

export function createKdfWorkerPool(options: KdfWorkerPoolOptions): KdfWorkerPool {
    return new BoundedKdfWorkerPool(options);
}
