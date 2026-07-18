/** Read-only orchestration for bounded remote channel-key derivation batches. */
import { decodeCloudBlob, settingsRevision, type DecodedCloudBlob } from './cloudBlob';
import {
    KdfError,
    REMOTE_KDF_VERSION,
    isKdfError,
    type KdfDeriveResponse,
    type KdfRevisionResponse,
} from './contracts';
import type { KdfWorkerPool } from './pool';

export interface RemoteKdfService {
    initialize(): Promise<void>;
    derive(
        authenticatedAccountId: string,
        storedBlob: string,
        cloudKey: string,
        channelId: string,
    ): Promise<KdfDeriveResponse>;
    revision(storedBlob: string): KdfRevisionResponse;
    close(): Promise<void>;
}

export type CloudBlobDecoder = (storedBlob: string, cloudKey: string) => Promise<DecodedCloudBlob>;

class InMemoryRemoteKdfService implements RemoteKdfService {
    private readonly activeAccounts = new Set<string>();

    constructor(
        private readonly pool: KdfWorkerPool,
        private readonly decoder: CloudBlobDecoder,
    ) {}

    initialize(): Promise<void> {
        return this.pool.initialize();
    }

    async derive(
        authenticatedAccountId: string,
        storedBlob: string,
        cloudKey: string,
        channelId: string,
    ): Promise<KdfDeriveResponse> {
        if (this.activeAccounts.has(authenticatedAccountId)) throw new KdfError('KDF_BUSY');
        this.activeAccounts.add(authenticatedAccountId);

        let decoded: DecodedCloudBlob | undefined;
        let lease: ReturnType<KdfWorkerPool['tryAcquire']> | undefined;
        try {
            lease = this.pool.tryAcquire();
            decoded = await this.decoder(storedBlob, cloudKey);
            const keys = [];
            for (let slot = 0; slot < decoded.passwords.length; slot += 1) {
                keys.push({
                    slot,
                    key: await lease.derive(decoded.passwords[slot], channelId),
                });
            }
            return {
                version: REMOTE_KDF_VERSION,
                settingsRevision: decoded.settingsRevision,
                keys,
            };
        } catch (error) {
            if (isKdfError(error)) throw error;
            if (
                typeof error === 'object'
                && error !== null
                && 'code' in error
                && error.code === 'KDF_BUSY'
            ) {
                throw new KdfError('KDF_BUSY');
            }
            throw new KdfError('KDF_FAILED');
        } finally {
            decoded?.passwords.fill('');
            lease?.release();
            this.activeAccounts.delete(authenticatedAccountId);
        }
    }

    revision(storedBlob: string): KdfRevisionResponse {
        return {
            version: REMOTE_KDF_VERSION,
            settingsRevision: settingsRevision(storedBlob),
        };
    }

    close(): Promise<void> {
        this.activeAccounts.clear();
        return this.pool.close();
    }
}

export function createRemoteKdfService(
    pool: KdfWorkerPool,
    decoder: CloudBlobDecoder = decodeCloudBlob,
): RemoteKdfService {
    return new InMemoryRemoteKdfService(pool, decoder);
}
