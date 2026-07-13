# GoofCord Cloud Server

This service syncs opaque GoofCord settings payloads using Discord OAuth and MongoDB.

## First deployment

This hardening work assumes a **clean start**: use a new, empty MongoDB database and allow the server to create its indexes during startup. Existing databases containing legacy plaintext tokens must not be pointed at this version until an offline migration has been reviewed and run from a verified backup.

1. Copy `.env.example` to `.env` and set `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, and a MongoDB URI.
2. Set `REDIRECT_URI` to the public base URL, with no path. The server appends `/v1/callback`; for local development use `http://localhost:3000`.
3. Run `bun install --frozen-lockfile`, then `bun run start`.
4. Check `GET /healthz`. It returns `200 OK` only after index initialization and while MongoDB is connected; otherwise it returns `503` without diagnostic details.

The service deliberately does not listen if its initial MongoDB connection fails. On `SIGTERM` or `SIGINT`, it stops accepting connections before disconnecting from MongoDB.

## Configuration

`.env.example` documents every runtime setting. The safe defaults are a 1 MiB `/save` body limit, a five-second MongoDB server-selection timeout, bounded in-memory rate-limit keys, and a 15-minute session-activity update interval. `PORT` and all numeric limits are validated at startup.

Do not commit `.env`, OAuth secrets, MongoDB credentials, tokens, or database dumps. The Docker build excludes local environment files and checkouts.

## Local Docker development

The application image is built from the exact `oven/bun:1.3.13` release, installs the committed lockfile with `--frozen-lockfile`, and runs as the unprivileged `bun` user.

```bash
cp .env.example .env
docker compose --profile dev-mongo up --build
```

The optional `dev-mongo` profile starts `mongo:8.0.15` and publishes its unauthenticated development database only on `127.0.0.1:${MONGO_PORT:-27017}`. It is for local development only; it is not a production database configuration. Compose defaults `PORT` and `HOST_PORT` to `3000`, and forwards every hardening setting into the application container. The container healthcheck requests `/healthz`.

No helper stops or removes a pre-existing generic MongoDB container. To remove this project's development data explicitly, use `docker compose --profile dev-mongo down -v` only when that deletion is intended.

## Production TLS, proxies, and MongoDB

For deployed mode, terminate TLS at a reverse proxy and set `ENFORCE_HTTPS=true`. Set `TRUSTED_PROXY_CIDRS` to only the proxy addresses or networks, and ensure the Bun service is reachable solely from that proxy or a private container network. The server only honors `X-Forwarded-For` and `X-Forwarded-Proto` when the direct Bun peer is trusted. Its trusted-proxy policy accepts exactly one forwarded client address and one forwarded protocol value; comma-separated forwarding chains are ignored. Trusting forwarded headers while allowing direct public access permits clients to spoof them.

Local HTTP is supported only when HTTPS enforcement is explicitly disabled. With enforcement enabled, insecure non-local requests are rejected; responses known to be HTTPS receive HSTS.

Any reachable MongoDB deployment needs authentication, a least-privileged application user, network isolation, and TLS whenever traffic crosses an untrusted network. Put its credential-bearing URI in runtime configuration, never in an image or source file.

## Built with

- [Bun](https://bun.sh/)
- [Hono](https://hono.dev/)
- [MongoDB](https://www.mongodb.com/)

## License

GNU General Public License; see [LICENSE](LICENSE).
