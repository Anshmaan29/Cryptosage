# Cryptosage

**Policy-Driven Post-Quantum Secure Messaging System with Automated Security Evaluation**

Cryptosage is a B.Tech research prototype for one-to-one messaging. Two local Python clients authenticate each other, negotiate a permitted post-quantum KEM and optional X25519, and exchange authenticated ciphertext through a separate WebSocket relay. A browser interface presents conversations, contact verification, protocol events, controlled attack experiments, and real benchmarks.

The custom protocol is for study and testing. It has not received a formal security proof or independent cryptographic review and must not be used for sensitive communications.

## Try the browser prototype

Open [Cryptosage](https://crytosage.anshmaansingh.workers.dev/) in a modern browser, create a private chat, and share its invite with one person. Each browser runs the cryptography locally. Cloudflare routes encrypted packets between the two browsers. The hosted demo has temporary room history. See [browser build and trust model](docs/BROWSER-DEMO.md).

## What runs

| Component | Implementation |
| --- | --- |
| Local clients | Python 3.12+, FastAPI, HTML/CSS/JavaScript |
| Relay | Separate Python `websockets` process; routes encrypted envelopes |
| Identity signatures | ML-DSA-65; persistent local identity and SHA-256 fingerprint pins |
| Default KEM | ML-KEM-768, NIST security level 3 |
| Other native KEMs | ML-KEM-512 and ML-KEM-1024. HQC-1, HQC-3 and HQC-5 are experimental. |
| Hybrid mode | Ephemeral X25519 combined with the selected KEM when both policies permit it |
| Message protection | Negotiated AES-256-GCM or ChaCha20-Poly1305, HKDF-SHA-256, separate directional hash chains |
| Evaluation | pytest, controlled packet mutations, repeated trials, JSON/CSV and matplotlib charts |

HQC-3 follows the implementation's 2025-08-22 specification. This build does not expose the older HQC-192 identifier. HQC is selected for future standardization; this project's HQC implementation remains experimental. The default policy excludes it from sessions. There is no substitute KEM or mock encryption when an implementation is unavailable.

## Install on Linux or macOS

Use Python 3.12 or newer, Git, and a working C compiler. On macOS, install the Xcode Command Line Tools with `xcode-select --install`. On Linux, install your distribution's Python venv support and C build tools if absent. The setup script installs pinned CMake and Ninja into the project virtual environment and builds only the required liboqs algorithms.

From the repository root:

```sh
./scripts/setup.sh
```

If `python3` points to an older Python, select the intended interpreter explicitly:

```sh
PYTHON=python3.12 ./scripts/setup.sh
```

The scripts pin the direct Python dependencies, CMake, Ninja, liboqs and its Python bindings. `requirements-lock.txt` records transitive versions for reproduction.

The native library is installed under `.local/`; its pinned official source and build cache are under `.build/`. No system-wide liboqs install is required. The script verifies exact source revisions and exercises real KEM and signature operations. The cryptographic build disables OpenSSL dependency use, so OpenSSL development headers are not a prerequisite.

V3 was built and exercised on an Apple M4 running macOS 27.2 with Python 3.14.3. The earlier Linux reports describe earlier revisions. See [the macOS verification record](docs/MACOS-V3.md).

## Run the demonstration

```sh
./scripts/run_demo.sh
```

The launcher initializes persistent test identities, starts the relay on port 8765, and starts Alice and Bob on ports 8001 and 8002. Open [Alice](http://127.0.0.1:8001) and [Bob](http://127.0.0.1:8002) in your browser. Stop the foreground launcher with Ctrl+C or run `./scripts/stop_demo.sh` in another terminal.

Before the first conversation:

1. Open **Verify identity** on Alice's screen and on Bob's screen.
2. Compare Alice's own fingerprint on Alice's screen with the Alice contact fingerprint on Bob's screen. Paste the independently checked value into Bob's verification input.
3. Repeat the comparison for Bob, then pin Bob's fingerprint in Alice's client.
4. On one client, select **Establish secure session**. Wait for both clients to report an authenticated session, then send messages in either direction.

The local public-contact directory helps the demo discover identities. It does not confer trust. A signed key from an unknown contact is rejected until the fingerprint is explicitly pinned. In a real remote use case, compare fingerprints through a separate trusted channel.

To run components in separate terminals:

```sh
.venv/bin/python -m scripts.init_demo
.venv/bin/python -m server.relay
.venv/bin/python -m client.app --name Alice --port 8001
.venv/bin/python -m client.app --name Bob --port 8002
```

Each client can also use an independent `--data-dir`, `--contacts-dir`, and `--policy`. Clients bind only to loopback. Private operations and decrypted messages belong to the local client process, while the relay has routing metadata and ciphertext. The local browser is part of the trusted endpoint.

### Delivery and storage

The message status moves from **Pending** to **Sent to relay** when the relay reports forwarding it. **Delivered** requires an authenticated receipt after the recipient saves the message. An interrupted send or missing receipt may leave delivery unconfirmed. Establish a fresh session with the same verified contact and use **Retry delivery** on the original message.

New macOS profiles use Keychain by default. For existing filesystem-backed profiles, migration is explicit and retains the original key file for recovery. See [Keychain migration and fallback](docs/SECURITY.md#storage-and-endpoint-exposure).

## Evaluate

```sh
./scripts/run_tests.sh
./scripts/run_benchmarks.sh --trials 100 --profile localhost --output reports/macos-localhost
./scripts/run_benchmarks.sh --trials 30 --profile constrained --output reports/macos-constrained
```

`pytest` executes the implementation's tests. `scripts.evaluate` creates a security report from the current run. `scripts.benchmark` measures both available level-3 KEMs, complete authenticated protocol computation, and separate loopback WebSocket exchanges, then writes real JSON, CSV, and charts. Review the commands' exit status and generated reports; an old report is not evidence that the current run passed.

The **Security lab** in either client presents session state and events. Its attack experiments use fresh, isolated client pairs and real cryptographic operations. Their results do not mutate the current conversation. The benchmark action runs repeated trials and shows unavailable measurements explicitly. Detailed methodology and limitations are in [Evaluation](docs/EVALUATION.md).

## Change the policy

The default file is [`policy/policy.json`](policy/policy.json). Restart the affected clients after editing it, or start a client with `--policy path/to/policy.json`.

Selection applies both policies and installed capabilities. It first rejects algorithms below either minimum level, prohibited algorithms, and experimental algorithms lacking both clients' opt-in. It then sorts by implementation/policy status, combined priority, comparable measured preference scores, and identifier. Security conditions outrank performance. See [Policy](docs/POLICY.md) for laboratory examples.

## Source map

```text
client/       Local client process and browser interface
server/       Untrusted WebSocket relay
crypto/       Strict liboqs and cryptography adapters
protocol/     Identity pins, signed handshake, directional ratchet
policy/       JSON policy and deterministic selection
attacks/      Controlled malicious-relay packet experiments
benchmarks/   Measurements, aggregation, reports and graphs
tests/        Primitive, policy, protocol, API and integration tests
scripts/      Installation, demo launch, evaluation and benchmarks
docs/         Architecture, threat model, demo and viva notes
reports/      Actual evaluation outputs
```

Read the [V1 audit and V2 evidence](docs/AUDIT.md), [Architecture and protocol](docs/ARCHITECTURE.md), [Threat model and limitations](docs/SECURITY.md), [Demo and viva](docs/DEMO.md), and [Troubleshooting](docs/TROUBLESHOOTING.md).

## Scope

The project supports one-to-one text conversations and fresh authenticated sessions. Conversation history and identity files are encrypted at rest using AES-GCM. New macOS profiles keep the storage key in Keychain. Passphrase and filesystem modes are available for fresh profiles. Live session and ratchet keys remain in memory and are discarded on reconnect. It has no group chat, file transfer, voice/video, multi-device synchronization, production certificate infrastructure, or optional X25519 hybrid mode. The hash ratchet is simpler than Signal's Double Ratchet. Python cannot guarantee erasure of every secret copy. Filesystem-backed profiles and retained migration keys require separate protection.

[Two-laptop LAN demo and contact cards](docs/TWO-LAPTOP-DEMO.md)
