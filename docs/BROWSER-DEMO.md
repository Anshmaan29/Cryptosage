# Hosted browser prototype

The browser demo uses a different endpoint runtime from the macOS application. Each browser generates its own ML-DSA-65 identity, runs liboqs 0.16.0 compiled to WebAssembly, and derives and uses AES-256-GCM message keys through Web Crypto. Cloudflare serves the browser assets and routes encrypted message envelopes through a two-slot Durable Object. The relay can observe room identifiers, roles, public handshake fields, packet lengths and timing.

Create a private chat and share its invite with one person through a trusted channel. The invite fragment contains a 256-bit secret. It is stripped from the address bar when the page loads and is absent from HTTP requests to Cloudflare. The browsers authenticate the signed exchange using the invite secret and pin the peer key for that room. Anyone who obtains the invite can claim the guest slot. The invite verifies possession of the shared secret, so send it directly to the intended person.

ML-KEM-768 is the default. To test HQC-3, the host must choose it and the guest must explicitly join with the experimental algorithm. Both browsers verify the selected KEM before using it. A signed, authenticated exchange confirms shared keys before enabling the composer. **Delivered** means the recipient browser authenticated the packet and accepted the message in its current room session.

Room history, keys and duplicate records live in browser memory. Reloading ends that endpoint session. When a socket reconnects within the same page, the peer requires a fresh handshake and retains up to 512 duplicate records for the current room. The browser Security Lab displays the active room state and runs isolated tampering, replay and negotiation checks using real browser protocol operations. Its benchmark measures real KEM operations on the current device. The hosted browser protocol and macOS wire protocol are separate. The macOS edition provides Keychain storage, persistent history and the broader native Security Lab. Use test data in the hosted edition.

## Build and check

From the repository root on the prepared Mac:

```bash
./scripts/setup.sh
./scripts/build_browser_crypto.sh
.venv/bin/python -m scripts.bundle_browser_worker
node --test scripts/check_browser_protocol.mjs
```

The build uses pinned liboqs source from `.build/liboqs` and a project-local Emscripten SDK. The worker module is generated at `.build/browser-worker.mjs`. It includes only the public browser assets and the liboqs license. Cloudflare deployment uses a SQLite-backed Durable Object binding called `ROOMS` for the `ChatRoom` class. The relay stores no conversation history in the Durable Object database.
