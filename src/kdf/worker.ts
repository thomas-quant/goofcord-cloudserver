/**
 * Dedicated remote-KDF worker entry.
 *
 * Argon2id is deliberately synchronous here: this module is loaded only by a
 * Bun Worker, never by the primary HTTP runtime. Inputs and outputs are not
 * cached or logged. Mutable byte arrays are cleared on a best-effort basis;
 * the managed runtime cannot guarantee that every internal copy is erased.
 */
import { argon2id } from '@noble/hashes/argon2';
import { utf8ToBytes } from '@noble/hashes/utils';

declare var self: Worker;

const OPTS = {
    t: 3,
    m: 65536,
    p: 1,
    dkLen: 32,
    version: 0x13,
} as const;

const SELF_TEST_PASSWORD = 'goofcryptspikevector';
const SELF_TEST_CHANNEL = '1234567890123456789';
const SELF_TEST_KEY = new Uint8Array([
    88, 212, 83, 25, 57, 47, 174, 59, 190, 19, 9, 128, 131, 89, 130, 17,
    233, 183, 232, 77, 56, 210, 16, 176, 20, 165, 100, 68, 226, 205, 232, 4,
]);

const CHANNEL_ID = /^[0-9]{1,20}$/;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_PASSWORD_UTF8_BYTES = 256;

interface SelfTestRequest {
    version: 1;
    type: 'self-test';
    requestId: string;
}

interface DeriveRequest {
    version: 1;
    type: 'derive';
    requestId: string;
    password: string;
    channelId: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
    const keys = Object.keys(value);
    return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function isRequestId(value: unknown): value is string {
    return typeof value === 'string' && REQUEST_ID.test(value);
}

function isSelfTestRequest(value: unknown): value is SelfTestRequest {
    return isRecord(value)
        && hasExactKeys(value, ['version', 'type', 'requestId'])
        && value.version === 1
        && value.type === 'self-test'
        && isRequestId(value.requestId);
}

function isDeriveRequest(value: unknown): value is DeriveRequest {
    if (!isRecord(value) || !hasExactKeys(value, ['version', 'type', 'requestId', 'password', 'channelId'])) {
        return false;
    }
    if (
        value.version !== 1
        || value.type !== 'derive'
        || !isRequestId(value.requestId)
        || typeof value.password !== 'string'
        || value.password.length === 0
        || typeof value.channelId !== 'string'
        || !CHANNEL_ID.test(value.channelId)
    ) {
        return false;
    }
    const passwordBytes = utf8ToBytes(value.password);
    try {
        return passwordBytes.length <= MAX_PASSWORD_UTF8_BYTES;
    } finally {
        passwordBytes.fill(0);
    }
}

function derive(password: string, channelId: string): Uint8Array {
    const passwordBytes = utf8ToBytes(password);
    const saltBytes = utf8ToBytes(channelId);
    try {
        return argon2id(passwordBytes, saltBytes, OPTS);
    } finally {
        passwordBytes.fill(0);
        saltBytes.fill(0);
    }
}

function selfTest(): boolean {
    const key = derive(SELF_TEST_PASSWORD, SELF_TEST_CHANNEL);
    try {
        if (key.length !== SELF_TEST_KEY.length) return false;
        for (let i = 0; i < key.length; i += 1) {
            if (key[i] !== SELF_TEST_KEY[i]) return false;
        }
        return true;
    } finally {
        key.fill(0);
    }
}

function fail(): void {
    self.postMessage({
        version: 1,
        type: 'error',
        ok: false,
        error: 'KDF_WORKER_FAILED',
    });
}

self.onmessage = (event: MessageEvent<unknown>) => {
    const request = event.data;
    try {
        if (isSelfTestRequest(request)) {
            if (!selfTest()) return fail();
            self.postMessage({
                version: 1,
                type: 'self-test',
                requestId: request.requestId,
                ok: true,
            });
            return;
        }
        if (isDeriveRequest(request)) {
            const key = derive(request.password, request.channelId);
            try {
                self.postMessage({
                    version: 1,
                    type: 'derive',
                    requestId: request.requestId,
                    ok: true,
                    key: Buffer.from(key).toString('base64'),
                });
            } finally {
                key.fill(0);
            }
            return;
        }
        fail();
    } catch {
        fail();
    }
};
