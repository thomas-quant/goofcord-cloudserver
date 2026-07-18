/** Strict version-1 remote-KDF schemas and resource bounds. */
export const REMOTE_KDF_VERSION = 1;
export const MAX_CHANNEL_ID_LENGTH = 20;
export const MAX_CLOUD_KEY_UTF8_BYTES = 1024;
export const MAX_PASSWORD_SLOTS = 8;
export const MAX_PASSWORD_UTF8_BYTES = 256;
export const MAX_STORED_BLOB_BYTES = 1024 * 1024;
export const MAX_DECOMPRESSED_SETTINGS_BYTES = 256 * 1024;

export const KDF_ERROR_CODES = [
    'INVALID_REQUEST',
    'UNAUTHORIZED',
    'CLOUD_SETTINGS_MISSING',
    'PASSWORDS_NOT_SYNCED',
    'CLOUD_DECRYPT_FAILED',
    'KDF_BUSY',
    'KDF_FAILED',
] as const;

export type KdfErrorCode = typeof KDF_ERROR_CODES[number];

export const KDF_ERROR_STATUS: Record<KdfErrorCode, number> = {
    INVALID_REQUEST: 400,
    UNAUTHORIZED: 401,
    CLOUD_SETTINGS_MISSING: 404,
    PASSWORDS_NOT_SYNCED: 409,
    CLOUD_DECRYPT_FAILED: 422,
    KDF_BUSY: 429,
    KDF_FAILED: 500,
};

export interface KdfDeriveRequest {
    version: 1;
    channelId: string;
    cloudEncryptionKey: string;
}

export interface KdfDerivedKey {
    slot: number;
    key: string;
}

export interface KdfDeriveResponse {
    version: 1;
    settingsRevision: string;
    keys: KdfDerivedKey[];
}

export interface KdfRevisionResponse {
    version: 1;
    settingsRevision: string;
}

export interface KdfErrorResponse {
    version: 1;
    error: { code: KdfErrorCode };
}

export type KdfContractResult<T> =
    | { ok: true; value: T }
    | { ok: false; error: 'INVALID_REMOTE_KDF_CONTRACT' };

const CHANNEL_ID = /^[0-9]{1,20}$/;
const REVISION = /^[A-Za-z0-9_-]{43}$/;
const KEY_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

function valid<T>(value: T): KdfContractResult<T> {
    return { ok: true, value };
}

function invalid<T>(): KdfContractResult<T> {
    return { ok: false, error: 'INVALID_REMOTE_KDF_CONTRACT' };
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
    const keys = Object.keys(value);
    if (keys.length !== expected.length) return false;
    return expected.every((key) => keys.includes(key));
}

function isErrorCode(value: unknown): value is KdfErrorCode {
    return typeof value === 'string' && (KDF_ERROR_CODES as readonly string[]).includes(value);
}

function isRevision(value: unknown): value is string {
    return typeof value === 'string' && REVISION.test(value);
}

function isCanonicalKey(value: unknown): value is string {
    if (typeof value !== 'string' || !KEY_BASE64.test(value)) return false;
    const decoded = Buffer.from(value, 'base64');
    return decoded.length === 32 && decoded.toString('base64') === value;
}

export function parseDeriveRequest(value: unknown): KdfContractResult<KdfDeriveRequest> {
    if (!isRecord(value) || !hasExactKeys(value, ['version', 'channelId', 'cloudEncryptionKey'])) {
        return invalid();
    }
    if (value.version !== REMOTE_KDF_VERSION || typeof value.channelId !== 'string' || !CHANNEL_ID.test(value.channelId)) {
        return invalid();
    }
    if (
        typeof value.cloudEncryptionKey !== 'string'
        || value.cloudEncryptionKey.length === 0
        || Buffer.byteLength(value.cloudEncryptionKey, 'utf8') > MAX_CLOUD_KEY_UTF8_BYTES
    ) {
        return invalid();
    }
    return valid(value as unknown as KdfDeriveRequest);
}

export function createDeriveRequest(channelId: string, cloudEncryptionKey: string): KdfContractResult<KdfDeriveRequest> {
    return parseDeriveRequest({ version: REMOTE_KDF_VERSION, channelId, cloudEncryptionKey });
}

export function parseDeriveResponse(value: unknown): KdfContractResult<KdfDeriveResponse> {
    if (!isRecord(value) || !hasExactKeys(value, ['version', 'settingsRevision', 'keys'])) return invalid();
    if (value.version !== REMOTE_KDF_VERSION || !isRevision(value.settingsRevision) || !Array.isArray(value.keys)) {
        return invalid();
    }
    if (value.keys.length === 0 || value.keys.length > MAX_PASSWORD_SLOTS) return invalid();
    for (let slot = 0; slot < value.keys.length; slot += 1) {
        const entry = value.keys[slot];
        if (!isRecord(entry) || !hasExactKeys(entry, ['slot', 'key'])) return invalid();
        if (entry.slot !== slot || !isCanonicalKey(entry.key)) return invalid();
    }
    return valid(value as unknown as KdfDeriveResponse);
}

export function parseRevisionResponse(value: unknown): KdfContractResult<KdfRevisionResponse> {
    if (!isRecord(value) || !hasExactKeys(value, ['version', 'settingsRevision'])) return invalid();
    if (value.version !== REMOTE_KDF_VERSION || !isRevision(value.settingsRevision)) return invalid();
    return valid(value as unknown as KdfRevisionResponse);
}

export function parseErrorResponse(value: unknown): KdfContractResult<KdfErrorResponse> {
    if (!isRecord(value) || !hasExactKeys(value, ['version', 'error'])) return invalid();
    if (value.version !== REMOTE_KDF_VERSION || !isRecord(value.error) || !hasExactKeys(value.error, ['code'])) {
        return invalid();
    }
    if (!isErrorCode(value.error.code)) return invalid();
    return valid(value as unknown as KdfErrorResponse);
}
