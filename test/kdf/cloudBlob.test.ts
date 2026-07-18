import { describe, expect, test } from 'bun:test';
import { createCipheriv, createHash, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { brotliCompressSync } from 'node:zlib';

import {
    SCRYPT_KEY_LENGTH,
    SCRYPT_OPTIONS,
    brotliDecompressBounded,
    decodeCloudBlob,
    settingsRevision,
} from '../../src/kdf/cloudBlob';
import {
    MAX_DECOMPRESSED_SETTINGS_BYTES,
    MAX_KDF_REQUEST_BODY_BYTES,
    MAX_STORED_BLOB_BYTES,
} from '../../src/kdf/contracts';

const SALT = new Uint8Array(32).fill(0x31);
const IV = new Uint8Array(12).fill(0x32);
const CLOUD_KEY = 'public synthetic cloud key';

interface CloudFixtures {
    encrypted: {
        cloudEncryptionKey: string;
        blob: string;
        expectedSettings: { encryptionPasswords: string[] };
    };
    wrongKey: { cloudEncryptionKey: string; blob: string };
    passwordless: { blob: string };
    malformed: Array<{ blob: string; expectedError: string }>;
}

const fixtures = JSON.parse(readFileSync(
    new URL('../fixtures/remoteKdf/cloud-blobs-v1.json', import.meta.url),
    'utf8',
)) as CloudFixtures;

function concatBytes(chunks: Uint8Array[]): Uint8Array {
    const output = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.length;
    }
    return output;
}

function encryptCompressed(compressed: Uint8Array, cloudKey = CLOUD_KEY): string {
    const key = Uint8Array.from(scryptSync(cloudKey, SALT, SCRYPT_KEY_LENGTH, SCRYPT_OPTIONS));
    try {
        const cipher = createCipheriv('aes-256-gcm', key, IV);
        const ciphertext = concatBytes([
            Uint8Array.from(cipher.update(compressed)),
            Uint8Array.from(cipher.final()),
        ]);
        const combined = concatBytes([SALT, IV, Uint8Array.from(cipher.getAuthTag()), ciphertext]);
        return Buffer.from(combined).toString('base64');
    } finally {
        key.fill(0);
    }
}

function encryptSettings(settings: unknown): string {
    return encryptCompressed(Uint8Array.from(brotliCompressSync(JSON.stringify(settings))));
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
    try {
        await promise;
        throw new Error('expected failure');
    } catch (error) {
        expect(error).toMatchObject({ code, message: code });
    }
}

describe('strict GoofCord cloud blob decoder', () => {
    test('freezes exact resource and scrypt options', () => {
        expect(MAX_KDF_REQUEST_BODY_BYTES).toBe(4096);
        expect(SCRYPT_KEY_LENGTH).toBe(32);
        expect(SCRYPT_OPTIONS).toEqual({ N: 32768, r: 8, p: 3, maxmem: 268435456 });
    });

    test('decrypts the Stage 1 fixture and preserves exact password order and bytes', async () => {
        const result = await decodeCloudBlob(
            fixtures.encrypted.blob,
            fixtures.encrypted.cloudEncryptionKey,
        );

        expect(result.passwords).toEqual(fixtures.encrypted.expectedSettings.encryptionPasswords);
        expect(result.passwords).toEqual([
            'goofcryptspikevector',
            '  public synthetic café 🔐 password  ',
        ]);
        expect(result.settingsRevision).toBe(createHash('sha256')
            .update(fixtures.encrypted.blob, 'utf8')
            .digest('base64url'));
        expect(settingsRevision(fixtures.encrypted.blob)).toBe(result.settingsRevision);
    });

    test('recognizes bounded Brotli-only objects first but never accepts their passwords', async () => {
        await expectCode(
            decodeCloudBlob(fixtures.passwordless.blob, CLOUD_KEY),
            'PASSWORDS_NOT_SYNCED',
        );

        const maliciousPasswordless = brotliCompressSync(JSON.stringify({
            encryptionPasswords: ['must never be accepted'],
        })).toString('base64');
        await expectCode(decodeCloudBlob(maliciousPasswordless, CLOUD_KEY), 'PASSWORDS_NOT_SYNCED');
    });

    test('maps canonical wrong-key/corrupt blobs to cloud-decrypt failure', async () => {
        await expectCode(
            decodeCloudBlob(fixtures.wrongKey.blob, fixtures.wrongKey.cloudEncryptionKey),
            'CLOUD_DECRYPT_FAILED',
        );
        await expectCode(decodeCloudBlob(fixtures.malformed[1].blob, CLOUD_KEY), 'CLOUD_DECRYPT_FAILED');

        const tampered = Uint8Array.from(Buffer.from(fixtures.encrypted.blob, 'base64'));
        tampered[44] ^= 0x01;
        await expectCode(
            decodeCloudBlob(Buffer.from(tampered).toString('base64'), fixtures.encrypted.cloudEncryptionKey),
            'CLOUD_DECRYPT_FAILED',
        );
    });

    test('rejects noncanonical and outer-bound input as invalid requests', async () => {
        await expectCode(decodeCloudBlob('', CLOUD_KEY), 'INVALID_REQUEST');
        await expectCode(decodeCloudBlob(fixtures.malformed[0].blob, CLOUD_KEY), 'INVALID_REQUEST');
        await expectCode(decodeCloudBlob('A'.repeat(MAX_STORED_BLOB_BYTES + 4), CLOUD_KEY), 'INVALID_REQUEST');
    });

    test('distinguishes missing passwords from malformed authenticated password lists', async () => {
        await expectCode(decodeCloudBlob(encryptSettings({ theme: 'dark' }), CLOUD_KEY), 'PASSWORDS_NOT_SYNCED');
        await expectCode(decodeCloudBlob(encryptSettings({ encryptionPasswords: [] }), CLOUD_KEY), 'PASSWORDS_NOT_SYNCED');

        const malformed = [
            { encryptionPasswords: 'not-an-array' },
            { encryptionPasswords: [''] },
            { encryptionPasswords: [123] },
            { encryptionPasswords: Array.from({ length: 9 }, () => 'x') },
            { encryptionPasswords: ['é'.repeat(129)] },
        ];
        for (const settings of malformed) {
            await expectCode(decodeCloudBlob(encryptSettings(settings), CLOUD_KEY), 'CLOUD_DECRYPT_FAILED');
        }
    });

    test('rejects authenticated invalid UTF-8, JSON, and non-object settings', async () => {
        const invalidUtf8 = Uint8Array.from(brotliCompressSync(Uint8Array.from([0xc3, 0x28])));
        await expectCode(decodeCloudBlob(encryptCompressed(invalidUtf8), CLOUD_KEY), 'CLOUD_DECRYPT_FAILED');

        const invalidJson = Uint8Array.from(brotliCompressSync('{'));
        await expectCode(decodeCloudBlob(encryptCompressed(invalidJson), CLOUD_KEY), 'CLOUD_DECRYPT_FAILED');
        await expectCode(decodeCloudBlob(encryptSettings(['not', 'an', 'object']), CLOUD_KEY), 'CLOUD_DECRYPT_FAILED');
    });

    test('uses asynchronous Brotli and enforces maxOutputLength before returning output', async () => {
        const nearLimit = Uint8Array.from(brotliCompressSync(
            new Uint8Array(MAX_DECOMPRESSED_SETTINGS_BYTES).fill(0x61),
        ));
        let timerFired = false;
        const timer = setTimeout(() => {
            timerFired = true;
        }, 0);
        const decompressed = await brotliDecompressBounded(nearLimit);
        clearTimeout(timer);
        expect(decompressed.length).toBe(MAX_DECOMPRESSED_SETTINGS_BYTES);
        expect(timerFired).toBe(true);
        decompressed.fill(0);

        const bomb = Uint8Array.from(brotliCompressSync(
            new Uint8Array(MAX_DECOMPRESSED_SETTINGS_BYTES + 1).fill(0x61),
        ));
        await expect(brotliDecompressBounded(bomb)).rejects.toThrow();
    });
});
