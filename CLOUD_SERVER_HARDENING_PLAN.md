# GoofCord Cloud Server Hardening Plan

## Project context and scope

This is a personal fork that is not currently serving production traffic. The implementation is exclusively scoped to `goofcord-cloudserver`; the GoofCord client will not be modified.

Before implementation, choose one data path:

- **Clean start (default):** discard any development database and create the new schemas and indexes directly. No legacy migration is required.
- **Preserve legacy data:** stop the service, back up MongoDB, and run the optional offline migration in this plan before starting the hardened server.

There is no zero-downtime or rolling-deployment requirement.

The server will support up to 10 active installations per Discord user. When an 11th installation authenticates, one of the least-recently-used sessions will be revoked automatically.

Because the session list is strictly bounded, sessions will be embedded in the user document:

```text
User
├── userId
└── sessions (maximum 10)
    ├── tokenHash
    ├── createdAt
    └── lastUsedAt
```

MongoDB's `$push`, `$sort`, and `$slice` operators can add a session, order the sessions, and retain at most 10 in one atomic update. Session activity will be refreshed at most once every 15 minutes to avoid writing to MongoDB on every request. This is intentionally a coarse-grained LRU policy rather than an exact record of every request.

## Compatibility contract

The following client-facing behavior will not change:

- `GET /v1/clientid`
- `GET /v1/login`
- `GET /v1/callback?code=...`
- The callback response remains `{ "token": "<32-character token>" }`.
- GoofCord continues sending the raw token through the `Authorization` header without a mandatory `Bearer` prefix.
- `/save`, `/load`, and `/delete` retain their current request and response formats.
- Existing settings payloads remain opaque and unchanged.
- `/delete` remains available as `GET` because the current client depends on it.
- If the optional migration is used, existing raw client tokens remain valid after migration.

Comprehensive OAuth `state` validation is deferred because the current GoofCord Vencord authorization path does not carry state and the client is out of scope. Login CSRF/session confusion remains an explicitly accepted residual risk until the client flow can be changed.

Server-side settings encryption is also deferred. When a cloud encryption key is configured, GoofCord encrypts settings locally and excludes the key from the uploaded payload. Without a key, GoofCord excludes fields marked as sensitive but only compresses and base64-encodes the remaining settings; those remaining settings are not confidential at rest on the server.

## Parallel implementation structure

The implementation can use three parallel workstreams alongside a primary integrator. Commit order remains dependency-ordered and does not need to match the order in which isolated work is developed.

### Wave 0: serial foundation

The primary integrator first establishes the shared contracts that the parallel work requires:

- Add the initial test and type-check scripts and common test helpers.
- Finalize environment-variable names, defaults, validation, and shared configuration types.
- Refactor `src/routes/v1.ts` into a thin composition layer without changing any endpoint behavior.
- Define the interfaces through which authentication, settings, security middleware, and direct-peer request information will be connected.
- Establish the explicit route-registration pattern.
- Retain sole ownership of `package.json` and `bun.lock` so parallel dependency requests cannot corrupt or conflict in the lockfile.

Wave 0 must leave existing API behavior intact and all available checks passing.

### Wave 1: parallel implementation

After the Wave 0 contracts are stable, the following workstreams can run concurrently with exclusive file ownership:

| Owner | Exclusive ownership | Responsibilities |
| --- | --- | --- |
| Authentication/data | Schema files, `src/auth/**`, `src/services/settings/**`, and focused authentication/data tests | Token hashing, bounded sessions, indexes, session activity, settings invariants, and deletion behavior |
| Security middleware | `src/security/**` and focused security tests | Body limiting, bounded rate limiting, trusted client-IP resolution, HTTPS enforcement, security headers, and sanitized errors |
| Runtime/operations | `src/index.ts`, `src/runtime/**`, `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.env.example`, `README.md`, and focused runtime/container tests | MongoDB startup, explicit route loading, readiness, shutdown, direct-peer plumbing, Docker, Compose, and deployment documentation |
| Primary integrator | `src/routes/v1.ts`, `package.json`, `bun.lock`, CI files, integration-test infrastructure, and final wiring | API compatibility, dependency changes requested by other workstreams, route composition, integration tests, and staged-diff review |

Workstreams must not edit files owned by another workstream. When a dependency, environment variable, route hook, or shared type is needed, the workstream reports the requested interface to the primary integrator rather than modifying the hotspot directly.

Cross-cutting behavior such as client-IP resolution must have one shared implementation. HTTPS enforcement and rate limiting must consume that implementation rather than parse forwarded headers independently.

### Wave 2: integration and optional migration

After the first parallel wave:

- The primary integrator connects the exported authentication, settings, security, and runtime modules through the thin route and application composition layers.
- Authentication/data may implement the optional migration only after the stored session schema and indexes are final.
- Runtime/operations completes environment and deployment documentation using the finalized configuration names.
- Security middleware completes tests that require real direct-peer context and full route ordering.
- Dependency and lockfile changes are applied centrally by the primary integrator.

The optional migration must not be developed against a provisional schema.

### Wave 3: parallel validation

Validation can again run concurrently:

- Authentication/data runs session, concurrency, duplicate-data, deletion, and optional migration tests.
- Security middleware runs request-boundary, limiter, forwarded-header, HTTPS, and error-response tests.
- Runtime/operations runs failed-startup, readiness, shutdown, Compose, Docker, and image-content checks.
- The primary integrator runs the complete suite, client compatibility review, CI validation, and final staged-diff audit.

Any integration fix is made by the owner of the affected file. The primary integrator coordinates the fix instead of editing across ownership boundaries unless ownership has explicitly been handed back for final integration.

## Commit instructions

Use small, dependency-ordered commits that leave the repository buildable and tested. Parallel development results should be assembled in the recommended dependency order even if they were implemented concurrently. The existing history uses short imperative commit subjects, so conventional-commit prefixes are not required.

### Commit rules

- Make each commit represent one reviewable behavior or operational concern.
- Add or update focused tests in the same commit as the behavior they verify.
- Keep `package.json` and `bun.lock` changes in the same commit as the code that needs the dependency.
- Keep schema changes and their corresponding application logic together. If the optional migration is implemented, commit the migration and its migration-specific tests together after the new schema behavior is stable.
- Do not create intermediate commits that knowingly fail type checking or tests.
- Do not mix unrelated formatting, generated files, or cleanup into a functional commit.
- Never commit `.env`, credentials, raw tokens, database dumps, `node_modules`, logs, coverage output, or local editor state.
- The untracked `GoofCord/` client checkout is reference material and is outside this repository's implementation scope. Do not stage or commit it.
- Prefer staging explicit paths with `git add <paths>` instead of `git add .` or `git add -A`.
- Do not bypass hooks with `--no-verify`. Fix the failing check or document a genuine tooling blocker before proceeding.

### Recommended commit sequence

The exact file boundaries may change during implementation, but preserve this dependency order:

1. **`Add cloud server hardening plan`**
   - Commit only `CLOUD_SERVER_HARDENING_PLAN.md`.
   - Do not include the untracked GoofCord client checkout.
2. **`Add test and configuration foundations`**
   - Add `test` and `typecheck` scripts, shared environment parsing, initial test helpers, and configuration tests.
   - Include any required dependency and lockfile changes.
3. **`Add hashed multi-session authentication`**
   - Add the session schema, token hashing helpers, atomic bounded-session login, session authentication/touch behavior, indexes, and focused concurrency tests.
4. **`Enforce settings and deletion invariants`**
   - Add the unique settings invariant, atomic settings upsert, all-session account deletion semantics, retryable standalone deletion order, and tests.
5. **`Harden server startup and health checks`**
   - Add explicit route registration, fail-fast MongoDB startup, validated ports, direct-peer address plumbing, readiness behavior, timeouts, and graceful shutdown tests.
6. **`Add request limits and rate limiting`**
   - Add pre-parse body limits, malformed-JSON handling, bounded IP/session limiters, `Retry-After`, sanitized global errors, and boundary tests.
7. **`Enforce trusted proxy and HTTPS rules`**
   - Add shared forwarded-header resolution, trusted-proxy enforcement, HTTPS rejection, HSTS, cache/referrer headers, and proxy-spoofing tests.
8. **`Harden container and MongoDB development setup`**
   - Add `.dockerignore`, the pinned non-root Docker build, corrected Compose defaults/environment, healthcheck, and a loopback-only pinned development MongoDB command/profile.
9. **`Add hardening checks to CI`**
   - Run type checking, tests, Compose rendering, and any practical container checks in CI alongside CodeQL.
10. **`Add optional legacy data migration`** — only if legacy data will be retained
    - Add preflight, idempotent migration, explicit index creation, aggregate reporting, and migration fixtures/tests.
11. **`Document hardened server deployment`**
    - Update `.env.example` and `README.md` with setup, proxy/TLS, MongoDB, limits, health, clean-start/migration, and first-deployment instructions.

If two adjacent commits cannot be made independently correct—for example, runtime peer-address plumbing and the first middleware that consumes it—combine them and explain the single concern in the commit body. Do not split implementation from its tests merely to preserve the suggested count.

### Checks before every commit

Run the checks that exist at that point in the implementation:

```bash
git status --short
git diff --check
git diff --cached --check
git diff --cached
bun run typecheck
bun run test
```

For container or deployment commits, also run:

```bash
docker compose config
docker build --check .
docker build -t goofcord-cloudserver:test .
```

Before creating the commit, confirm that `git diff --cached` contains only the intended files and no secret values. After committing, run `git status --short` again and preserve any unrelated user-owned changes.

### Example for committing this plan

Because the plan and GoofCord client checkout are currently both untracked, stage the plan explicitly:

```bash
git add CLOUD_SERVER_HARDENING_PLAN.md
git diff --cached --check
git diff --cached
git commit -m "Add cloud server hardening plan"
git status --short
```

## Workstream A: authentication and data integrity

### Token storage

- Continue generating tokens with `randomBytes(16).toString("hex")` so the client receives the same 32-character format.
- Return the raw token only in the successful callback response.
- Store `SHA-256(rawToken)` as a canonical lowercase 64-character hexadecimal string.
- Hash every incoming raw `Authorization` value before querying MongoDB.
- Use the token hash, never the raw token, as an in-memory rate-limit key.
- Never log raw tokens, authorization headers, OAuth codes, settings bodies, or token hashes.
- Do not introduce expiration, refresh tokens, or a mandatory `Bearer` prefix.
- Add `Cache-Control: no-store`, `Pragma: no-cache`, and a restrictive referrer policy to the token-bearing callback response.

### Bounded coarse-LRU sessions

On successful OAuth login:

1. Generate the raw token and its SHA-256 hash.
2. Atomically upsert the user by `userId`.
3. Push a session whose `createdAt` and `lastUsedAt` use the same server timestamp.
4. Sort sessions by `lastUsedAt` descending, then `createdAt` descending, then `tokenHash` ascending as a deterministic tie-breaker.
5. Retain the first 10 sessions with `$slice`.
6. Return the raw token using the existing callback response.

The implementation must retry the upsert if simultaneous first logins race on the unique `userId` index. A token-hash duplicate-key error must generate a new token and retry, even though a random collision is practically impossible.

On authenticated API use:

- Locate the user through the token-hash index.
- Update only the matching session's `lastUsedAt`, and only when it is more than 15 minutes old.
- Include the age condition in the atomic update so concurrent requests do not all perform the refresh.
- Keep authentication failures compatible with GoofCord's existing `401` handling.

### Database invariants

- Add a unique index on `users.userId`.
- Add a unique multikey index on `users.sessions.tokenHash` to prevent a token from belonging to different users.
- Explicitly prevent duplicate token hashes within an individual user's session array; MongoDB's unique multikey index does not enforce uniqueness within one document.
- Enforce a maximum of 10 sessions through atomic write logic and validate the invariant in tests.
- Add a unique index on `settings.userId`.
- Use atomic upserts for users and settings.
- Disable automatic production index creation when using the optional migration; let the migration create indexes only after validation. For a clean empty database, an explicit index-initialization step may create them during first setup.

### Settings and account deletion

- `/save` atomically upserts one settings document per `userId`.
- `/delete` deletes the user's settings and revokes all sessions by deleting the user document.
- Keep the operation idempotent so repeated deletion returns the existing compatible success response.
- If MongoDB is a replica set or sharded cluster, a transaction may make the cross-collection deletion atomic.
- On a standalone MongoDB deployment, delete settings before the user. If user deletion then fails, the still-valid session can retry; the reverse order can leave inaccessible orphaned settings.
- Document that strict cross-collection atomicity and perfect coordination with an already in-flight `/save` require a transaction or a more complex deletion-state design and are not required for this personal deployment.

## Optional offline migration

Skip this entire section for a clean start.

If legacy tokens or settings must be retained, the migration will run while the service is stopped and will:

1. Perform a read-only preflight and report aggregate counts of duplicates, malformed documents, and conflicts.
2. Consolidate duplicate user documents by Discord `userId`.
3. Convert every distinct legacy plaintext `authToken` into a hashed session.
4. Detect a legacy token assigned to different user IDs before creating the global unique token-hash index. Abort for manual resolution rather than silently choosing an owner.
5. Derive deterministic legacy session timestamps from the document `_id` timestamp when possible, with a documented fixed fallback for non-ObjectId values.
6. Deduplicate session hashes inside each user and retain the 10 newest sessions using the same deterministic sort order as the application.
7. Consolidate duplicate settings documents, preserving the document with the greatest `_id` as the best available deterministic proxy for the newest record.
8. Remove all legacy plaintext token fields.
9. Verify that every retained user has a valid non-empty session list, no plaintext tokens remain, no user has more than 10 sessions, and hashes are globally unique.
10. Create the unique indexes only after data validation succeeds.

The migration must:

- Be safe to resume after a partial failure and safe to run more than once.
- Refuse to proceed past preflight when it cannot preserve an invariant.
- Report aggregate counts without printing user IDs, settings, raw tokens, OAuth codes, or token hashes.
- Be tested against a disposable database copy before it is used on data that matters.
- Require a verified backup before changing retained data.

## Workstream B: runtime, deployment, and availability

### Configuration and startup

- Validate all required environment variables before connecting or listening.
- Parse and validate `PORT` as an integer in the valid TCP port range rather than silently falling back for malformed values.
- Replace dynamic filesystem route discovery with explicit imports and route registration.
- Do not swallow route-import or route-registration failures.
- Await `mongoose.connect()` and do not start the HTTP service unless the initial connection succeeds.
- Log a successful database connection only after it has actually succeeded.
- Configure an appropriate MongoDB server-selection timeout and avoid unbounded request hangs.
- Disable or tightly bound Mongoose command buffering so database outages fail requests predictably.
- Install SIGTERM and SIGINT handlers that stop accepting new requests and close MongoDB cleanly.

### Health endpoint

- Add an unauthenticated health/readiness endpoint with no sensitive diagnostic details.
- Return `200` only when the process is ready and Mongoose is connected.
- Return `503` when Mongoose is disconnected or disconnecting.
- Add a container healthcheck that uses this endpoint.
- Exempt the health endpoint from session authentication, but protect it with the general IP limiter if one is enabled.

### Docker Compose and environment example

- Pass `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, `MONGO_URI`, `PORT`, and all hardening configuration into the container.
- Give `PORT` and `HOST_PORT` safe Compose defaults.
- Ensure the published container target port matches the application's configured port.
- Remove the obsolete Compose `version` field.
- Document copying `.env.example` to `.env`.
- Keep `.env` out of both Git and the Docker build context.

Document `REDIRECT_URI` as the server base URL because the server appends `/v1/callback`:

```dotenv
REDIRECT_URI=http://localhost:3000
```

### Reproducible and minimal container builds

- Add a restrictive `.dockerignore` covering at least `.env*`, `.git`, `node_modules`, coverage, editor files, logs, and unrelated local checkouts.
- Copy `package.json` and `bun.lock` before dependency installation.
- Run `bun install --frozen-lockfile`.
- Pin the Bun image to an exact release; a digest is optional for this personal deployment.
- Use a multi-stage build or otherwise ensure the runtime image contains only required production dependencies and application files.
- Run the final container as the unprivileged `bun` user.
- Add explicit `test` and `typecheck` package scripts.

### Development and production MongoDB safety

- Replace the current destructive `dockerMongo` command with a pinned development setup or Compose profile.
- Bind an unauthenticated development MongoDB only to `127.0.0.1`, never all host interfaces.
- Do not unconditionally stop or remove an existing container by a generic name.
- Document that any reachable deployment must use authentication, a least-privileged application user, network isolation, and TLS when traffic crosses an untrusted network.
- Keep MongoDB credentials only in runtime configuration, never in the image.

### HTTPS and trusted proxies

Support two explicit modes:

- **Local development:** HTTPS enforcement may be disabled explicitly, allowing local HTTP and Docker port forwarding.
- **Deployed mode:** HTTPS enforcement is enabled, TLS terminates at a reverse proxy, and the Bun application is reachable only from that proxy or a private container network.

The implementation must:

- Obtain the direct peer address from Bun's server API and pass it into the Hono request context.
- Never use the request `Host` header to decide whether a request is local.
- Ignore `X-Forwarded-For` and `X-Forwarded-Proto` from untrusted peers.
- Trust forwarded headers only when the direct peer matches configured proxy addresses/networks or a precisely documented trusted-hop policy.
- Use the same resolved client IP for HTTPS enforcement and rate limiting.
- Reject insecure non-local requests with a stable error when HTTPS enforcement is enabled.
- Add HSTS only to responses known to have arrived through HTTPS.
- Document that enabling forwarded-header trust without restricting direct access permits spoofing.

## Workstream C: abuse protection and error handling

### Request limits

- Apply a configurable default maximum of 1 MiB to the entire `/save` request body, including its JSON envelope.
- Install the Hono body-limit middleware before authentication-independent body parsing and before `c.req.json()`.
- Reject an excessive `Content-Length` immediately and count streamed bytes when the header is absent or inaccurate.
- Set a Bun-level `maxRequestBodySize` as an outer safety boundary.
- Measure bytes, not JavaScript character count.
- Return `413 Payload Too Large` for oversized requests.
- Return `400 Bad Request` for malformed JSON or a non-string `settings` field.
- Do not include or log the malformed request body.
- Keep `/load` compatible with existing opaque settings payloads.

### Rate limiting

Rate limits will be configurable and use conservative defaults:

- Apply a pre-authentication IP bucket before database token lookup on protected endpoints.
- Apply a stricter IP bucket before the OAuth callback performs external Discord requests.
- Apply a separate authenticated session bucket to `/save`, `/load`, and `/delete` after authentication.
- Do not use a single combined `session+IP` key as the only protection.
- Return `429 Too Many Requests` with an integer-seconds `Retry-After` header.

The initial implementation may use an in-memory limiter because the deployment has one service instance. It must have TTL-based cleanup and a hard maximum number of stored keys so arbitrary source addresses cannot cause unbounded memory growth. Restarts reset the limits, and horizontal scaling would require a shared limiter or enforcement at the reverse proxy.

### Error handling and security headers

- Add a global error handler that returns stable, non-sensitive errors.
- Do not expose exception messages, stack traces, database details, Discord responses, or configuration values to clients.
- Distinguish expected `400`, `401`, `413`, and `429` responses from unexpected `500` failures.
- Add at least `X-Content-Type-Options: nosniff` and an appropriate referrer policy to API responses.
- Ensure authenticated and token-bearing responses are not cached.

## Validation plan

### Authentication and data tests

- Raw tokens are always 32 lowercase hexadecimal characters.
- MongoDB stores only 64-character hashes, never new raw tokens.
- Ten installations can authenticate simultaneously.
- An 11th authentication removes a session selected by the documented deterministic coarse-LRU ordering.
- A refresh older than 15 minutes updates only the matching session.
- Requests inside the refresh interval do not produce repeated database writes.
- Concurrent first logins produce one user document and successful bounded sessions.
- Concurrent logins never leave more than 10 sessions.
- Reauthentication on one installation does not invalidate every other installation.
- Duplicate hashes cannot exist within one user or across different users.
- `/delete` removes settings and revokes all sessions while retaining the compatible response.

### Request and proxy tests

- A request exactly at the configured body limit is accepted and one byte over is rejected with `413`.
- Limits work with multibyte UTF-8, missing `Content-Length`, and a false `Content-Length`.
- Malformed JSON returns `400`.
- IP and session limits are independent and return `429` with `Retry-After`.
- Limiter storage remains bounded and expired keys are removed.
- A direct request cannot use forged forwarded headers to appear secure or change its client IP.
- Forwarded headers from a configured proxy are interpreted according to the documented hop policy.
- Local development HTTP works only when explicitly configured.
- Secure deployed responses include HSTS; insecure deployed requests are rejected.

### Runtime and container tests

- The process does not listen when MongoDB is unavailable.
- A required route-registration failure prevents startup.
- Health returns `200` when ready and `503` after a database disconnect.
- Shutdown closes the HTTP server and MongoDB connection.
- `docker compose config` succeeds with defaults and maps the correct target port.
- The Docker build uses the committed lockfile and a pinned Bun release.
- The final container runs as a non-root user.
- A sentinel `.env` and unrelated local files are absent from the built image.
- The regular CI workflow runs type checking and the full test suite in addition to CodeQL.

### Optional migration tests

Run these only if the optional migration is implemented:

- A pre-existing raw client token remains usable after migration.
- Duplicate users and settings migrate deterministically.
- A cross-user legacy token conflict aborts safely before indexes are created.
- A partially completed migration resumes without duplicate sessions or data loss.
- Running the completed migration again makes no changes.
- MongoDB contains no plaintext tokens after migration.

## Acceptance criteria

Implementation is complete only when all applicable validation tests pass and:

- No client endpoint, method, request format, response format, or token format changes.
- Existing opaque cloud payloads save and load without transformation.
- No raw tokens, authorization headers, OAuth codes, or settings bodies are logged.
- Session and settings database invariants are enforced under concurrent requests.
- Oversized and malformed settings requests receive the correct status.
- Normal GoofCord autosave remains below the configured body and rate limits.
- Proxy spoofing cannot bypass HTTPS enforcement or IP rate limits.
- Local development remains usable through explicit configuration.
- Startup, readiness, and shutdown behavior accurately reflect MongoDB availability.
- Docker builds are reproducible, minimal, non-root, and do not contain local secrets.
- The development MongoDB helper cannot expose an unauthenticated database beyond loopback.
- If legacy data is preserved, the optional migration criteria also pass.

## First-deployment checklist

1. Choose a clean database or the optional legacy-data path.
2. If retaining data, verify a backup and test the migration against a disposable copy.
3. Configure the application, MongoDB credentials, reverse proxy, TLS, and network restrictions.
4. Run type checking, tests, Compose rendering, and the pinned Docker build.
5. If retaining data, stop the old service and run the offline migration.
6. Start the hardened server and verify readiness.
7. Smoke-test login, save, load, delete, body limits, rate limits, HTTPS enforcement, and an existing token if migrated.
8. Review sanitized error logs and retain any backup until the retained data has been verified.

## Estimate

For a clean database, expected effort is approximately 16–24 engineering hours. Implementing and validating the optional legacy migration is expected to add roughly 4–8 hours, depending on the quality of the existing data.
