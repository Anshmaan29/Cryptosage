# Hosted browser prototype

The browser demo uses a different endpoint runtime from the macOS application. Each browser generates its own ML-DSA-65 identity, runs liboqs 0.16.0 compiled to WebAssembly, and derives and uses AES-256-GCM message keys through Web Crypto. Cloudflare serves the browser assets and routes encrypted message envelopes through a two-slot Durable Object. The relay can observe room identifiers, roles, public handshake fields, packet lengths and timing.

Create a private chat and share its invite with one person through a trusted channel. The invite fragment contains a 256-bit secret. It is stripped from the address bar when the page loads and is absent from HTTP requests to Cloudflare. The browsers authenticate the signed exchange using the invite secret and pin the peer key for that room. Anyone who obtains the invite can claim the guest slot. The invite verifies possession of the shared secret, so send it directly to the intended person.

New rooms use browser protocol v2. Open **Policy manager** before creating or joining a room to set a minimum security category, an allowlist, and a preferred key exchange. Browser policy preferences can be saved on this device. Both peers must explicitly allow experimental HQC-3. ML-KEM-768 and HQC-3 are the two compiled implementations and both are category 3. Setting category 5 deliberately leaves this browser with no eligible exchange.

The host's signed offer contains its policy and the public keys for its eligible algorithms. The guest independently selects from the intersection of both policies and signs its response, including its policy and a hash of the offer. An explicit preference adds one vote. If candidates tie, ML-KEM-768 wins. The host verifies the selection and both peers confirm the derived key before enabling the composer. If no candidate is allowed by both sides, the guest returns a signed refusal and the decision view explains both sides' exclusions. Saving policy changes in an open v2 room reconnects that browser and starts a fresh handshake. Original browser invites retain their fixed key exchange and must satisfy the joining browser's current policy.

**Protocol inspector** shows the authenticated key exchange, peer fingerprint and recent events. **Delivered** means the recipient browser authenticated and accepted the packet in the current room session. Room history, keys and duplicate records live in browser memory. Reloading ends the endpoint session. A reconnect requires a fresh handshake and retains up to 512 duplicate records in that tab. **Attack lab** runs isolated tampering, replay and negotiation checks, and **Benchmarks** measures KEM operations on the current device. **Research** links to the guided demo and recorded macOS evidence. The hosted browser protocol and macOS wire protocol are separate. Use test data in the hosted edition.

## Build and check

From the repository root on the prepared Mac:

```bash
./scripts/setup.sh
./scripts/build_browser_crypto.sh
.venv/bin/python -m scripts.bundle_browser_worker
node --test scripts/check_browser_protocol.mjs
```

The build uses pinned liboqs source from `.build/liboqs` and a project-local Emscripten SDK. The worker module is generated at `.build/browser-worker.mjs`. It includes only the public browser assets and the liboqs license. Cloudflare deployment uses a SQLite-backed Durable Object binding called `ROOMS` for the `ChatRoom` class. The relay stores no conversation history in the Durable Object database.
