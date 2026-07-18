import mongoose from 'mongoose';
import { loadConfig } from './config';
import { createAuthenticationService, initializeDataIndexes } from './auth';
import { createSettingsService } from './services/settings';
import { createSecurity } from './security';
import { createDiscordOAuthService } from './routes/v1Services';
import { createApplication } from './runtime/application';
import { configureMongo } from './runtime/mongo';
import { startRuntime, type RunningRuntime } from './runtime/server';
import { createKdfWorkerPool } from './kdf/pool';
import { createRemoteKdfService } from './kdf/service';

export async function startProductionServer(): Promise<RunningRuntime> {
    // Parse all configuration before making any outbound connections.
    const config = loadConfig();
    configureMongo(mongoose);

    const auth = createAuthenticationService({
        sessionTouchIntervalMs: config.sessionTouchIntervalMs,
    });
    const settings = createSettingsService();
    const security = createSecurity(config);
    const oauth = createDiscordOAuthService(config);
    const kdf = createRemoteKdfService(createKdfWorkerPool({
        capacity: config.kdfGlobalConcurrency,
        jobTimeoutMs: config.kdfJobTimeoutMs,
    }));

    const runtime = await startRuntime({
        config,
        mongo: mongoose,
        initializeIndexes: initializeDataIndexes,
        initializeKdf: () => kdf.initialize(),
        shutdownKdf: () => kdf.close(),
        createApplication: (readiness) => createApplication({
            clientId: config.clientId,
            auth,
            settings,
            oauth,
            security,
            kdf,
            readiness,
            mongoConnection: mongoose.connection,
        }),
        serve: (options) => Bun.serve(options),
    });

    console.log('Connected to MongoDB');
    console.log(`Running at http://localhost:${config.port}`);
    return runtime;
}

if (import.meta.main) {
    await startProductionServer().catch(() => {
        console.error('Unable to start server.');
        process.exitCode = 1;
    });
}
