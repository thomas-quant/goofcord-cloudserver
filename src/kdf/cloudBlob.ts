/**
 * Strict in-memory decoder for the current GoofCord cloud settings format.
 *
 * Brotli and scrypt are asynchronous on the primary runtime. Mutable byte
 * buffers are cleared best-effort; managed strings cannot be reliably erased.
 */
import { createDecipheriv, createHash, scrypt } from 'node:crypto';
import { promisify } from 'node:util';
import { brotliDecompress } from 'node:zlib';

import {
    KdfError,
    MAX_DECOMPRESSED_SETTINGS_BYTES,
    MAX_PASSWORD_SLOTS,
    MAX_PASSWORD_UTF8_BYTES,
    MAX_STORED_BLOB_BYTES,
    type KdfErrorCode,
} from './contracts';

export const SCRYPT_KEY_LENGTH = 32;
export const SCRYPT_OPTIONS = {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 268435456,
} as const;

const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = SALT_LENGTH + IV_LENGTH + TAG_LENGTH;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const decompressAsync = promisify(brotliDecompress);

export interface DecodedCloudBlob {
    passwords: string[];
    settingsRevision: string;
}

function fail(code: KdfErrorCode): never {
    throw new KdfError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function strictBase64(value: string): Uint8Array {
    if (
        value.length === 0
        || Buffer.byteLength(value, 'utf8') > MAX_STORED_BLOB_BYTES
        || value.length % 4 !== 0
        || !BASE64.test(value)
    ) {
        fail('INVALID_REQUEST');
    }

    const decoded = Buffer.from(value, 'base64');
    if (decoded.length > MAX_STORED_BLOB_BYTES || decoded.toString('base64') !== value) {
        decoded.fill(0);
        fail('INVALID_REQUEST');
    }
    const copy = Uint8Array.from(decoded);
    decoded.fill(0);
    return copy;
}

export async function brotliDecompressBounded(input: Uint8Array): Promise<Uint8Array> {
    const output = await decompressAsync(Uint8Array.from(input), {
        maxOutputLength: MAX_DECOMPRESSED_SETTINGS_BYTES,
    });
    const copy = Uint8Array.from(output);
    output.fill(0);
    return copy;
}

function parseObject(bytes: Uint8Array): Record<string, unknown> | null {
    try {
        const value = JSON.parse(UTF8.decode(bytes)) as unknown;
        return isRecord(value) ? value : null;
    } catch {
        return null;
    }
}

async function isPasswordlessObject(bytes: Uint8Array): Promise<boolean> {
    let decompressed: Uint8Array | undefined;
    try {
        decompressed = await brotliDecompressBounded(bytes);
        return parseObject(decompressed) !== null;
    } catch {
        return false;
    } finally {
        decompressed?.fill(0);
    }
}

async function deriveCloudKey(cloudKeyBytes: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        scrypt(cloudKeyBytes, salt, SCRYPT_KEY_LENGTH, SCRYPT_OPTIONS, (error, derived) => {
            if (error) return reject(error);
            const copy = Uint8Array.from(derived);
            derived.fill(0);
            resolve(copy);
        });
    });
}

function decrypt(combined: Uint8Array, key: Uint8Array): Uint8Array {
    const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = combined.subarray(SALT_LENGTH + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = combined.subarray(HEADER_LENGTH);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const first = Uint8Array.from(decipher.update(ciphertext));
    const last = Uint8Array.from(decipher.final());
    try {
        const output = new Uint8Array(first.length + last.length);
        output.set(first);
        output.set(last, first.length);
        return output;
    } finally {
        first.fill(0);
        last.fill(0);
    }
}

function validatePasswords(settings: Record<string, unknown>): string[] {
    if (!Object.prototype.hasOwnProperty.call(settings, 'encryptionPasswords')) {
        fail('PASSWORDS_NOT_SYNCED');
    }
    const passwords = settings.encryptionPasswords;
    if (Array.isArray(passwords) && passwords.length === 0) fail('PASSWORDS_NOT_SYNCED');
    if (!Array.isArray(passwords) || passwords.length > MAX_PASSWORD_SLOTS) fail('CLOUD_DECRYPT_FAILED');

    for (const password of passwords) {
        if (
            typeof password !== 'string'
            || password.length === 0
            || Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_UTF8_BYTES
        ) {
            fail('CLOUD_DECRYPT_FAILED');
        }
    }
    return passwords as string[];
}

export function settingsRevision(storedBlob: string): string {
    return createHash('sha256').update(storedBlob, 'utf8').digest('base64url');
}

export async function decodeCloudBlob(storedBlob: string, cloudKey: string): Promise<DecodedCloudBlob> {
    const combined = strictBase64(storedBlob);
    let cloudKeyBytes: Uint8Array | undefined;
    let derivedKey: Uint8Array | undefined;
    let compressed: Uint8Array | undefined;
    let decompressed: Uint8Array | undefined;

    try {
        if (await isPasswordlessObject(combined)) fail('PASSWORDS_NOT_SYNCED');
        if (combined.length <= HEADER_LENGTH) fail('CLOUD_DECRYPT_FAILED');

        cloudKeyBytes = Uint8Array.from(Buffer.from(cloudKey, 'utf8'));
        derivedKey = await deriveCloudKey(cloudKeyBytes, combined.subarray(0, SALT_LENGTH));
        compressed = decrypt(combined, derivedKey);
        decompressed = await brotliDecompressBounded(compressed);
        const settings = parseObject(decompressed);
        if (!settings) fail('CLOUD_DECRYPT_FAILED');

        return {
            passwords: validatePasswords(settings),
            settingsRevision: settingsRevision(storedBlob),
        };
    } catch (error) {
        if (error instanceof KdfError) throw error;
        throw new KdfError('CLOUD_DECRYPT_FAILED');
    } finally {
        cloudKeyBytes?.fill(0);
        derivedKey?.fill(0);
        compressed?.fill(0);
        decompressed?.fill(0);
        combined.fill(0);
    }
}
