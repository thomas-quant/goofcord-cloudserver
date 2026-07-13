import type { AppConfig } from '../config';

import type { MongoConnectionState } from './readiness';

export interface MongoRuntime {
    connection: MongoConnectionState;
    set(key: string, value: unknown): unknown;
    connect(uri: string, options: { serverSelectionTimeoutMS: number; bufferCommands: false }): Promise<unknown>;
    disconnect(): Promise<unknown>;
}

/**
 * Fail fast while MongoDB is unavailable. Query buffering otherwise converts
 * a short database outage into unbounded pending HTTP requests.
 */
export function configureMongo(mongo: MongoRuntime): void {
    mongo.set('bufferCommands', false);
}

export async function connectMongo(
    mongo: MongoRuntime,
    config: Pick<AppConfig, 'mongoUri' | 'mongoServerSelectionTimeoutMs'>,
): Promise<void> {
    await mongo.connect(config.mongoUri, {
        serverSelectionTimeoutMS: config.mongoServerSelectionTimeoutMs,
        bufferCommands: false,
    });
}
