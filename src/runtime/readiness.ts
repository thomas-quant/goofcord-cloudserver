export interface MongoConnectionState {
    readyState: number;
}

/** Mongoose's connected state. Other states include disconnected and disconnecting. */
export const MONGOOSE_CONNECTED = 1;

export interface Readiness {
    markReady(): void;
    markNotReady(): void;
    isReady(): boolean;
}

export function createReadiness(): Readiness {
    let ready = false;

    return {
        markReady: () => {
            ready = true;
        },
        markNotReady: () => {
            ready = false;
        },
        isReady: () => ready,
    };
}

/**
 * Readiness is deliberately stricter than process liveness: an HTTP server is
 * ready only after startup completes and while MongoDB remains connected.
 */
export function isReady(readiness: Readiness, connection: MongoConnectionState): boolean {
    return readiness.isReady() && connection.readyState === MONGOOSE_CONNECTED;
}
