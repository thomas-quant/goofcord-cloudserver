import { describe, expect, test } from 'bun:test';
import { createDecipheriv, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { brotliDecompressSync } from 'node:zlib';

const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = SALT_LENGTH + IV_LENGTH + TAG_LENGTH;
const SCRYPT_MAX_MEM = 128 * 32768 * 8 * 2;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

interface CloudFixtures {
    version: number;
    notice: string;
    encrypted: {
        cloudEncryptionKey: string;
        saltHex: string;
        ivHex: string;
        blob: string;
        expectedSettings: Record<string, unknown> & { encryptionPasswords: string[] };
    };
    wrongKey: { cloudEncryptionKey: string; blob: string; expectedError: string };
    passwordless: { blob: string; expectedSettings: Record<string, unknown>; expectedError: string };
    malformed: Array<{ name: string; blob: string; expectedError: string }>;
}

const fixtures = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/cloud-blobs-v1.json', import.meta.url),
    'utf8',
)) as CloudFixtures;

function strictBase64(value: string): Uint8Array {
    if (value.length === 0 || value.length % 4 !== 0 || !BASE64.test(value)) {
        throw new Error('invalid base64');
    }
    const decoded = Buffer.from(value, 'base64');
    if (decoded.toString('base64') !== value) throw new Error('noncanonical base64');
    return Uint8Array.from(decoded);
}

function decryptEncrypted(blob: string, cloudKey: string): Record<string, unknown> {
    const combined = strictBase64(blob);
    if (combined.length <= HEADER_LENGTH) throw new Error('invalid encrypted layout');

    const salt = combined.subarray(0, SALT_LENGTH);
    const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = combined.subarray(SALT_LENGTH + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = combined.subarray(HEADER_LENGTH);
    const key = Uint8Array.from(scryptSync(cloudKey, salt, 32, {
        N: 32768,
        r: 8,
        p: 3,
        maxmem: SCRYPT_MAX_MEM,
    }));
    try {
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const first = Uint8Array.from(decipher.update(ciphertext));
        const last = Uint8Array.from(decipher.final());
        const compressed = new Uint8Array(first.length + last.length);
        compressed.set(first);
        compressed.set(last, first.length);
        const decompressed = Uint8Array.from(brotliDecompressSync(compressed));
        return JSON.parse(Buffer.from(decompressed).toString('utf8')) as Record<string, unknown>;
    } finally {
        key.fill(0);
    }
}

function decodePasswordless(blob: string): Record<string, unknown> {
    const decompressed = Uint8Array.from(brotliDecompressSync(strictBase64(blob)));
    return JSON.parse(Buffer.from(decompressed).toString('utf8')) as Record<string, unknown>;
}

describe('synthetic GoofCord cloud blob fixtures', () => {
    test('decrypts the current encrypted format and preserves exact password order and bytes', () => {
        expect(fixtures.version).toBe(1);
        expect(fixtures.notice).toContain('PUBLIC SYNTHETIC TEST DATA');

        const combined = strictBase64(fixtures.encrypted.blob);
        expect(Buffer.from(combined.subarray(0, SALT_LENGTH)).toString('hex')).toBe(fixtures.encrypted.saltHex);
        expect(Buffer.from(combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)).toString('hex'))
            .toBe(fixtures.encrypted.ivHex);

        const settings = decryptEncrypted(fixtures.encrypted.blob, fixtures.encrypted.cloudEncryptionKey);
        expect(settings).toEqual(fixtures.encrypted.expectedSettings);
        expect(settings.encryptionPasswords).toEqual([
            'goofcryptspikevector',
            '  public synthetic café 🔐 password  ',
        ]);
    });

    test('fails AES-GCM authentication with the wrong cloud key before any Argon work exists', () => {
        expect(fixtures.wrongKey.blob).toBe(fixtures.encrypted.blob);
        expect(fixtures.wrongKey.expectedError).toBe('CLOUD_DECRYPT_FAILED');
        expect(() => decryptEncrypted(fixtures.wrongKey.blob, fixtures.wrongKey.cloudEncryptionKey)).toThrow();
    });

    test('decodes the Brotli-only passwordless format without a password list', () => {
        const settings = decodePasswordless(fixtures.passwordless.blob);
        expect(settings).toEqual(fixtures.passwordless.expectedSettings);
        expect(Object.prototype.hasOwnProperty.call(settings, 'encryptionPasswords')).toBe(false);
        expect(fixtures.passwordless.expectedError).toBe('PASSWORDS_NOT_SYNCED');
    });

    test('rejects noncanonical base64 and an undersized encrypted layout', () => {
        expect(fixtures.malformed.map((fixture) => fixture.expectedError))
            .toEqual(['INVALID_REQUEST', 'CLOUD_DECRYPT_FAILED']);
        expect(() => strictBase64(fixtures.malformed[0].blob)).toThrow('base64');
        expect(() => decryptEncrypted(fixtures.malformed[1].blob, fixtures.encrypted.cloudEncryptionKey))
            .toThrow('layout');
    });
});
