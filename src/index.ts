import mongoose from 'mongoose';
import { Hono } from "hono";
import { loadConfig } from './config';
import type { AppEnv } from './contracts';
import { createV1Router } from './routes/v1';
import { createDiscordOAuthService, createLegacyAuthenticationService, createLegacySettingsService } from './routes/v1Services';
import { permissiveRouteSecurity } from './routes/routeSecurity';
import v2 from './routes/v2';

const config = loadConfig();

await mongoose.connect(config.mongoUri).catch(console.error);
console.log('Connected to MongoDB');

export const app = new Hono<AppEnv>();

app.route('/v1', createV1Router({
    clientId: config.clientId,
    auth: createLegacyAuthenticationService(),
    settings: createLegacySettingsService(),
    oauth: createDiscordOAuthService(config),
    security: permissiveRouteSecurity,
}));
app.route('/v2', v2);

app.get('/', (c) => {
    return c.redirect("https://codeberg.org/wuemeli/goofcord-cloudserver");
})

const port = config.port;
console.log(`Running at http://localhost:${port}`)

export default {
    port,
    fetch: app.fetch,
}
