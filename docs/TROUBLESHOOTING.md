# Troubleshooting

## Python, compiler or native library unavailable

Check `python3 --version`, `git --version`, and `cc --version`. Select Python 3.12+ through `PYTHON=python3.12 ./scripts/setup.sh` when needed. On macOS install the Xcode Command Line Tools; on Linux install your distribution's compiler and Python venv packages.

Run the setup script from a terminal and preserve its failing output. It retains TLS verification and checks exact official source revisions. It refuses a changed cryptographic source tree; do not bypass that guard. Preserve local work, then use a clean build-cache directory or restore the intended source before retrying.

A `liboqs is unavailable` error means `.local/` is missing or incomplete. Run the setup script and its real-operation self-check. If using a custom trusted prefix, set `OQS_INSTALL_PATH` to that prefix before starting clients. A missing HQC build must appear unavailable rather than being replaced by a different algorithm.

## Ports are occupied

The normal ports are 8765 for the relay, 8001 for Alice and 8002 for Bob. Stop only the old processes you started, then rerun the launcher. Do not kill unrelated processes. To use different client ports, supply `--port` and open the matching local endpoint. A custom relay port also needs matching `--relay ws://127.0.0.1:PORT` on both clients.

## Relay connected but session unavailable

Both clients must be running, both must have the expected contact's key in their local contact directory, and both must explicitly pin that key. A one-sided trust decision is insufficient. Start a handshake from one side at a time. If both clients initiate simultaneously or a failed handshake remains pending, wait for its expiry and try again.

The browser's connection indicator distinguishes the relay connection from an authenticated messaging session. Reconnecting to the relay does not restore old session keys.

## Fingerprint mismatch or changed identity

Check the contact's own fingerprint through a trusted channel. Do not accept a different key simply because it has a valid signature. Persistent demo identities normally survive restarts. If a test identity was deliberately replaced, stop its clients, preserve old state, independently verify the replacement, and remove only the affected stale trust entry offline. Never reset another person's trust silently.

## Message replay, tampering or out-of-order rejection

The receiver displays no corrupted plaintext and does not advance its chain on an integrity failure. If an authentic next message was merely delayed, it can still be accepted when it arrives. If the relay dropped a message and later counters arrive first, start a new authenticated session. Use **Retry delivery** on an unconfirmed outgoing message. The ratchet keeps no skipped keys or offline delivery queue.

After stopping a client or relay, establish a new session before messaging. The app does not persist ratchet secrets for reuse after process restarts.

## Policy refuses establishment

Inspect both JSON policies and the event reason. Check minimum security level, prohibited rules, actual available algorithms, and both experimental opt-ins. The default refuses HQC-3 unless explicitly allowed by both clients. Changing JSON to call HQC recommended does not override the implementation's experimental status.

Restart clients after a policy-file change. Never relax a security condition merely to hide an expected policy-rejection test.

## Local API returns 403

Use the actual loopback client origin with its configured port. Untrusted Host/Origin values, cross-origin browser requests, or missing application tokens are rejected. The frontend obtains its token from local state and sends it for POST actions. Do not disable these checks to embed the client on another website or expose it publicly.

## Benchmarks or charts fail

Install `requirements.txt` into `.venv`, including psutil, pandas and matplotlib. Use a writable matplotlib cache directory when the user home is read-only, for example `MPLCONFIGDIR=/tmp/crytosage-matplotlib`. Keep output directories writable. A failed run must remain failed; inspect its error before retrying.

Use `python -m scripts.benchmark` for complete protocol computation and separate real loopback WebSocket measurements. The primitive runner alone explicitly lacks that adapter and must not be relabeled as a full network handshake. If local socket creation is unavailable, report the transport check as blocked; do not substitute a computation timing.

## Test report looks stale

Rerun `python -m scripts.evaluate` from the project virtual environment and inspect its exit code and current report timestamp. Do not present a previously successful file as the outcome of a newer failed command.
