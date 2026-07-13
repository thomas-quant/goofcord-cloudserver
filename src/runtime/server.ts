import type { AppConfig } from '../config';

import type { MongoRuntime } from './mongo';
import { connectMongo } from './mongo';
import { createShutdown, installShutdownHandlers, type StoppableServer } from './lifecycle';
import { createReadiness, type Readiness } from './readiness';

export interface DirectPeerServer extends StoppableServer {
    requestIP(request: Request): { address: string } | null;
}

export interface ServeOptions {
    port: number;
    maxRequestBodySize: number;
    fetch(request: Request, server: DirectPeerServer): Response | Promise<Response>;
}

export interface RuntimeDependencies {
    config: AppConfig;
    mongo: MongoRuntime;
    initializeIndexes(): Promise<void>;
    createApplication(readiness: Readiness): { fetch(request: Request, bindings?: { directPeerAddress?: string }): Response | Promise<Response> };
    serve(options: ServeOptions): DirectPeerServer;
    installSignals?: (shutdown: () => Promise<void>) => () => void;
}

export interface RunningRuntime {
    readiness: Readiness;
    server: DirectPeerServer;
    shutdown(): Promise<void>;
    disposeSignalHandlers(): void;
}

/**
 * Start only after MongoDB and the explicit clean-start indexes are available.
 * The injected boundary keeps lifecycle behavior testable without Bun or Mongo.
 */
export async function startRuntime(dependencies: RuntimeDependencies): Promise<RunningRuntime> {
    const readiness = createReadiness();
    const { config, mongo } = dependencies;
    let server: DirectPeerServer | undefined;

    try {
        await connectMongo(mongo, config);
        await dependencies.initializeIndexes();

        const application = dependencies.createApplication(readiness);
        server = dependencies.serve({
            port: config.port,
            maxRequestBodySize: config.maxRequestBodyBytes,
            fetch: (request, bunServer) => {
                const directPeerAddress = bunServer.requestIP(request)?.address;
                return application.fetch(request, { directPeerAddress });
            },
        });
        const shutdown = createShutdown(server, mongo, readiness);
        const disposeSignalHandlers = (dependencies.installSignals
            ?? ((handler) => installShutdownHandlers(handler)))(shutdown);

        readiness.markReady();
        return { readiness, server, shutdown, disposeSignalHandlers };
    } catch (error) {
        readiness.markNotReady();
        if (server) await Promise.resolve(server.stop(false)).catch(() => undefined);
        await mongo.disconnect().catch(() => undefined);
        throw error;
    }
}
