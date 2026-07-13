import type { MongoRuntime } from './mongo';
import type { Readiness } from './readiness';

export interface StoppableServer {
    stop(closeActiveConnections?: boolean): Promise<unknown> | unknown;
}

export interface SignalProcess {
    on(signal: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
    off(signal: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
    exitCode?: number | string;
}

export function createShutdown(
    server: StoppableServer,
    mongo: Pick<MongoRuntime, 'disconnect'>,
    readiness: Readiness,
): () => Promise<void> {
    let shutdownPromise: Promise<void> | undefined;

    return () => {
        shutdownPromise ??= (async () => {
            readiness.markNotReady();
            await server.stop(false);
            await mongo.disconnect();
        })();
        return shutdownPromise;
    };
}

/** Install idempotent graceful handlers and return a disposer for tests/embedding. */
export function installShutdownHandlers(
    shutdown: () => Promise<void>,
    processLike: SignalProcess = process,
    onFailure: () => void = () => {
        processLike.exitCode = 1;
    },
): () => void {
    let handlingSignal = false;
    const handler = () => {
        if (handlingSignal) return;
        handlingSignal = true;
        void shutdown().catch(onFailure);
    };

    processLike.on('SIGINT', handler);
    processLike.on('SIGTERM', handler);

    return () => {
        processLike.off('SIGINT', handler);
        processLike.off('SIGTERM', handler);
    };
}
