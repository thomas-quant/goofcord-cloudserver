# Remote KDF worker engine decision

Status: Stage 1 decision for quick task `260718-prx`.

## Decision

Use a dedicated Bun Worker running synchronous Argon2id from exact-pinned
`@noble/hashes` 1.8.0. The worker fixes the compatibility parameters in source:
Argon2id v19, 65,536 KiB memory, three passes, parallelism one, and 32 output
bytes. Passwords and Discord channel IDs enter as their exact UTF-8 bytes.

This engine was selected because the committed vector proves byte equality with
the GoofCrypt/stegcloak-rs path, it accepts the channel ID's arbitrary-length
salt unchanged, it returns raw key bytes, it adds no native build toolchain, and
the blocking 64 MiB operation runs outside the primary HTTP event loop.

`Bun.password` is not compatible with this protocol. Its public API generates
its own salt and returns a PHC string; it cannot accept the exact Discord channel
ID salt and return the required raw 32 bytes. A successful password-verification
API is not a substitute for byte-exact message-key output.

Native add-ons and subprocesses are unnecessary for the initial implementation.
A future engine may replace noble only if it passes this same exact vector and
preserves the isolation and resource bounds.

## Security boundary

The worker accepts one strictly-shaped message at a time. It does not log,
persist, or cache passwords, channel IDs, or derived keys. It clears mutable
input/key byte arrays on a best-effort basis, without claiming guaranteed erasure
from JavaScriptCore, noble's internal memory, the allocator, or the operating
system. Generic failures do not reflect request material.

The worker exposes a vector self-test command. Stage 2 must run that command
successfully before KDF readiness is enabled. A mismatch or worker error must
keep the service unready for remote derivation.

## Stage 2 handoff

Stage 2 remains responsible for the lifecycle and abuse-control layer:

- maintain a small global worker/concurrency cap sized for 64 MiB jobs;
- allow only one active derivation batch per authenticated account;
- derive password slots sequentially in their stored order;
- enforce queue, timeout, cancellation, worker-restart, and generic-error policy;
- decrypt settings and validate all bounds before dispatching Argon work;
- run the exact-vector self-test before readiness;
- never add server-side password or derived-key response caching.

No route, authentication, database, or readiness wiring is part of Stage 1.
