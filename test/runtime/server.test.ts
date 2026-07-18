import { describe, expect, test } from 'bun:test';

import { loadConfig } from '../../src/config';
import { startRuntime, type DirectPeerServer, type ServeOptions } from '../../src/runtime/server';
import type { MongoRuntime } from '../../src/runtime/mongo';
import { validEnvironment } from '../helpers/environment';

function createMongo(readyState = 1): MongoRuntime & { calls: string[] } {
    const calls: string[] = [];
    return {
        calls,
        connection: { readyState },
        set: () => undefined,
        async connect() {
            calls.push('connect');
        },
        async disconnect() {
            calls.push('disconnect');
        },
    };
}

function createServer(): DirectPeerServer & { stopped: boolean } {
    return {
        stopped: false,
        requestIP: () => ({ address: '203.0.113.10' }),
        async stop() {
            this.stopped = true;
        },
    };
}

describe('runtime lifecycle', () => {
    test('does not listen when MongoDB startup fails', async () => {
        const mongo = createMongo();
        mongo.connect = async () => {
            throw new Error('MongoDB unavailable');
        };
        let served = false;

        await expect(startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => undefined,
            initializeKdf: async () => undefined,
            shutdownKdf: async () => undefined,
            createApplication: () => ({ fetch: () => new Response('unused') }),
            serve: () => {
                served = true;
                return createServer();
            },
            installSignals: () => () => undefined,
        })).rejects.toThrow('MongoDB unavailable');

        expect(served).toBe(false);
        expect(mongo.calls).toEqual(['disconnect']);
    });

    test('initializes indexes before listening and binds Bun peer addresses', async () => {
        const mongo = createMongo();
        const calls: string[] = [];
        let options: ServeOptions | undefined;
        let bindings: { directPeerAddress?: string } | undefined;
        const server = createServer();

        const runtime = await startRuntime({
            config: loadConfig({ ...validEnvironment(), MAX_REQUEST_BODY_BYTES: '4321' }),
            mongo,
            initializeIndexes: async () => {
                calls.push('indexes');
            },
            initializeKdf: async () => {
                calls.push('kdf');
            },
            shutdownKdf: async () => {
                calls.push('kdf-close');
            },
            createApplication: () => ({
                fetch: (_request, receivedBindings) => {
                    bindings = receivedBindings;
                    return new Response('ok');
                },
            }),
            serve: (receivedOptions) => {
                calls.push('serve');
                options = receivedOptions;
                return server;
            },
            installSignals: () => () => undefined,
        });

        expect(mongo.calls).toEqual(['connect']);
        expect(calls).toEqual(['indexes', 'kdf', 'serve']);
        expect(options?.port).toBe(3000);
        expect(options?.maxRequestBodySize).toBe(4321);

        const response = await options?.fetch(new Request('http://localhost/'), server);
        expect(await response?.text()).toBe('ok');
        expect(bindings).toEqual({ directPeerAddress: '203.0.113.10' });
        expect(runtime.readiness.isReady()).toBe(true);
    });

    test('stops accepting connections and disconnects MongoDB during shutdown', async () => {
        const mongo = createMongo();
        const server = createServer();
        const runtime = await startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => undefined,
            initializeKdf: async () => undefined,
            shutdownKdf: async () => undefined,
            createApplication: () => ({ fetch: () => new Response('ok') }),
            serve: () => server,
            installSignals: () => () => undefined,
        });

        await Promise.all([runtime.shutdown(), runtime.shutdown()]);

        expect(runtime.readiness.isReady()).toBe(false);
        expect(server.stopped).toBe(true);
        expect(mongo.calls).toEqual(['connect', 'disconnect']);
    });

    test('cleans up the server if handler installation fails after listen', async () => {
        const mongo = createMongo();
        const server = createServer();

        await expect(startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => undefined,
            initializeKdf: async () => undefined,
            shutdownKdf: async () => undefined,
            createApplication: () => ({ fetch: () => new Response('ok') }),
            serve: () => server,
            installSignals: () => {
                throw new Error('signal setup failed');
            },
        })).rejects.toThrow('signal setup failed');

        expect(server.stopped).toBe(true);
        expect(mongo.calls).toEqual(['connect', 'disconnect']);
    });

    test('refuses to listen and closes KDF state when startup self-test fails', async () => {
        const mongo = createMongo();
        const calls: string[] = [];
        let served = false;

        await expect(startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => {
                calls.push('indexes');
            },
            initializeKdf: async () => {
                calls.push('kdf');
                throw new Error('KDF vector mismatch');
            },
            shutdownKdf: async () => {
                calls.push('kdf-close');
            },
            createApplication: () => ({ fetch: () => new Response('unused') }),
            serve: () => {
                served = true;
                return createServer();
            },
            installSignals: () => () => undefined,
        })).rejects.toThrow('KDF vector mismatch');

        expect(calls).toEqual(['indexes', 'kdf', 'kdf-close']);
        expect(served).toBe(false);
        expect(mongo.calls).toEqual(['connect', 'disconnect']);
    });

    test('shutdown order is unready, stop accepting, close KDF, then disconnect Mongo', async () => {
        const events: string[] = [];
        const mongo = createMongo();
        mongo.disconnect = async () => {
            events.push('mongo');
        };
        const server = createServer();
        server.stop = async () => {
            events.push('server');
        };
        const runtime = await startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => undefined,
            initializeKdf: async () => undefined,
            shutdownKdf: async () => {
                events.push('kdf');
            },
            createApplication: () => ({ fetch: () => new Response('ok') }),
            serve: () => server,
            installSignals: () => () => undefined,
        });

        await Promise.all([runtime.shutdown(), runtime.shutdown()]);
        expect(runtime.readiness.isReady()).toBe(false);
        expect(events).toEqual(['server', 'kdf', 'mongo']);
    });

    test('continues KDF and Mongo cleanup when stopping the listener fails', async () => {
        const events: string[] = [];
        const mongo = createMongo();
        mongo.disconnect = async () => {
            events.push('mongo');
        };
        const server = createServer();
        server.stop = async () => {
            events.push('server');
            throw new Error('stop failed');
        };
        const runtime = await startRuntime({
            config: loadConfig(validEnvironment()),
            mongo,
            initializeIndexes: async () => undefined,
            initializeKdf: async () => undefined,
            shutdownKdf: async () => {
                events.push('kdf');
            },
            createApplication: () => ({ fetch: () => new Response('ok') }),
            serve: () => server,
            installSignals: () => () => undefined,
        });

        await expect(runtime.shutdown()).rejects.toThrow('stop failed');
        expect(events).toEqual(['server', 'kdf', 'mongo']);
        expect(runtime.readiness.isReady()).toBe(false);
    });
});
