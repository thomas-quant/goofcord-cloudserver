import { describe, expect, test } from 'bun:test';

import {
    KDF_ERROR_CODES,
    KDF_ERROR_STATUS,
    MAX_CLOUD_KEY_UTF8_BYTES,
    MAX_DECOMPRESSED_SETTINGS_BYTES,
    MAX_PASSWORD_SLOTS,
    MAX_PASSWORD_UTF8_BYTES,
    MAX_STORED_BLOB_BYTES,
    createDeriveRequest,
    parseDeriveRequest,
    parseDeriveResponse,
    parseErrorResponse,
    parseRevisionResponse,
} from '../../src/kdf/contracts';
import type { KdfDeriveResponse, KdfErrorResponse } from '../../src/kdf/contracts';

const REVISION = 'A'.repeat(43);
const KEY_1 = 'WNRTGTkvrju+EwmAg1mCEem36E040hCwFKVkROLN6AQ=';
const KEY_2 = `${'A'.repeat(43)}=`;

describe('remote KDF v1 contracts', () => {
    test('accepts only the exact bounded derive request shape', () => {
        expect(createDeriveRequest('1', 'x')).toEqual({
            ok: true,
            value: { version: 1, channelId: '1', cloudEncryptionKey: 'x' },
        });
        expect(createDeriveRequest('9'.repeat(20), 'é'.repeat(MAX_CLOUD_KEY_UTF8_BYTES / 2)).ok).toBe(true);

        for (const channelId of ['', '1'.repeat(21), '-1', '1.0', '１２３', '1e3']) {
            expect(createDeriveRequest(channelId, 'x').ok).toBe(false);
        }
        expect(createDeriveRequest('1', '').ok).toBe(false);
        expect(createDeriveRequest('1', 'é'.repeat((MAX_CLOUD_KEY_UTF8_BYTES / 2) + 1)).ok).toBe(false);

        expect(parseDeriveRequest({ version: 1, channelId: '123', cloudEncryptionKey: 'key' }).ok).toBe(true);
        expect(parseDeriveRequest({ version: 1, channelId: '123', cloudEncryptionKey: 'key', userId: 'victim' }).ok)
            .toBe(false);
        expect(parseDeriveRequest({ version: 1, channelId: '123', cloudEncryptionKey: 'key', m: 8 }).ok)
            .toBe(false);
        expect(parseDeriveRequest({ version: 2, channelId: '123', cloudEncryptionKey: 'key' }).ok).toBe(false);
    });

    test('accepts only canonical 32-byte keys in stable contiguous slot order', () => {
        const valid: KdfDeriveResponse = { version: 1, settingsRevision: REVISION, keys: [
            { slot: 0, key: KEY_1 },
            { slot: 1, key: KEY_2 },
        ] };
        expect(parseDeriveResponse(valid)).toEqual({ ok: true, value: valid });

        const invalid = [
            { ...valid, keys: [] },
            { ...valid, keys: Array.from({ length: MAX_PASSWORD_SLOTS + 1 }, (_, slot) => ({ slot, key: KEY_1 })) },
            { ...valid, keys: [{ slot: 1, key: KEY_1 }] },
            { ...valid, keys: [{ slot: 0, key: KEY_1 }, { slot: 0, key: KEY_2 }] },
            { ...valid, keys: [{ slot: 0, key: KEY_1 }, { slot: 2, key: KEY_2 }] },
            { ...valid, keys: [{ slot: 0, key: KEY_1.slice(0, -1) }] },
            { ...valid, keys: [{ slot: 0, key: `${KEY_1.slice(0, -1)}!` }] },
            { ...valid, keys: [{ slot: 0, key: Buffer.alloc(31).toString('base64') }] },
            { ...valid, extra: true },
        ];
        for (const value of invalid) expect(parseDeriveResponse(value).ok).toBe(false);
    });

    test('freezes revision and error response shapes and status mapping', () => {
        expect(parseRevisionResponse({ version: 1, settingsRevision: REVISION }).ok).toBe(true);
        expect(parseRevisionResponse({ version: 1, settingsRevision: `${REVISION}=` }).ok).toBe(false);
        expect(parseRevisionResponse({ version: 1, settingsRevision: REVISION, extra: true }).ok).toBe(false);

        expect(KDF_ERROR_CODES).toEqual([
            'INVALID_REQUEST',
            'UNAUTHORIZED',
            'CLOUD_SETTINGS_MISSING',
            'PASSWORDS_NOT_SYNCED',
            'CLOUD_DECRYPT_FAILED',
            'KDF_BUSY',
            'KDF_FAILED',
        ]);
        expect(KDF_ERROR_STATUS).toEqual({
            INVALID_REQUEST: 400,
            UNAUTHORIZED: 401,
            CLOUD_SETTINGS_MISSING: 404,
            PASSWORDS_NOT_SYNCED: 409,
            CLOUD_DECRYPT_FAILED: 422,
            KDF_BUSY: 429,
            KDF_FAILED: 500,
        });
        for (const code of KDF_ERROR_CODES) {
            const response: KdfErrorResponse = { version: 1, error: { code } };
            expect(parseErrorResponse(response)).toEqual({ ok: true, value: response });
        }
        expect(parseErrorResponse({ version: 1, error: { code: 'WRONG_KEY' } }).ok).toBe(false);
        expect(parseErrorResponse({ version: 1, error: { code: 'KDF_FAILED', detail: 'secret' } }).ok).toBe(false);
    });

    test('exports the decoder bounds Stage 2 must enforce', () => {
        expect(MAX_PASSWORD_SLOTS).toBe(8);
        expect(MAX_PASSWORD_UTF8_BYTES).toBe(256);
        expect(MAX_STORED_BLOB_BYTES).toBe(1024 * 1024);
        expect(MAX_DECOMPRESSED_SETTINGS_BYTES).toBe(256 * 1024);
    });
});
