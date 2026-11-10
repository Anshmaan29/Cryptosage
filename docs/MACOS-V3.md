# Crytosage V3 macOS verification

The work began from `805c774` on the local `codex/macos-v3` branch. The checkout was empty before cloning. The host was an Apple M4 (`Mac16,12`, arm64), with 10 CPU cores and 16 GiB of RAM. macOS reported 27.2 (26B123). The project used Python 3.14.3, Apple clang 21.0.0, CMake 4.4.4 and Ninja 1.13.2. Homebrew was already available. The project built its pinned arm64 liboqs 0.16.0 and liboqs-python 0.16.0.2 locally. The setup script passed real ML-KEM-768 and HQC-3 encapsulation/decapsulation and ML-DSA-65 sign/verify checks.

## Verification on 8 November 2026

| Check | Observed result |
| --- | --- |
| Baseline at `805c774` | 234 passed, 87.90% line coverage, 65.82% for `client/app.py` |
| V3 macOS suite | 253 passed, 87.67% line coverage, 84.46% for `client/app.py` |
| WebSocket recovery | Two real clients exchanged messages simultaneously, recovered after relay loss, and retried the original logical message after a lost receipt and restart. The recipient stored one copy and issued a valid receipt for the fresh packet. |
| Algorithm selection | Default ML-KEM-768 session and an HQC-3 session after explicit policy opt-in by both real clients. |
| Relay boundary | The recovery test captured message envelopes containing only routing fields, the session and counter, and ciphertext. It checked that the plaintext and logical ID were absent. |
| Keychain | Native key creation and read-back, independent Keychain-backed demo clients, and a separate native migration fixture. Simulated Keychain access denial and an interrupted migration were covered by the suite. |
| Browser | Chrome desktop and 390 px mobile, light and dark, fingerprint pinning, bidirectional receipts, re-key, real attack and benchmark displays, keyboard dialog dismissal, and reduced-motion fallback. |
| Attack Lab | All 12 scenarios reached the expected rejection or safe abort. Re-key interruption used a private loopback relay. Other scenarios exercised isolated protocol validators. |
| Quality and dependencies | Ruff lint and format, MyPy across application packages and scripts, pip consistency and PyPI advisory scan passed. Bandit reported low-severity findings, chiefly test assertions and fixed executable calls. |
| Launcher | Local setup, start, duplicate-start rejection, stop, test and benchmark scripts executed. Separate processes bound to loopback. |

The Starlette test adapter emits a deprecation warning for its installed HTTPX integration. Raw evidence is local under `.build/v3-evidence/`, including baseline and final JUnit XML, test HTML, coverage HTML/XML, browser captures, attack JSON, and benchmark JSON/CSV/HTML. Reports contain synthetic lab identifiers and measured summaries. Private profiles and startup logs are excluded from the public site bundle.

## Benchmark results

Both algorithms were measured in each profile. The cells below show median and nearest-rank P95 in milliseconds. Each underlying report also provides mean, sample standard deviation, min/max, CPU, sampled RSS, application bytes, KEM operations, message cryptography, re-key and policy-selection timings.

| WebSocket profile | Samples per KEM | ML-KEM-768 median / P95 | HQC-3 median / P95 |
| --- | ---: | ---: | ---: |
| Localhost | 100 | 4.22 / 4.40 | 13.54 / 14.17 |
| Moderate, 25 ms added per send | 30 | 117.13 / 120.37 | 124.49 / 126.19 |
| Constrained, 100 ms per send and 256 kb/s modeled payload rate | 30 | 1194.66 / 1196.64 | 1545.54 / 1548.37 |

Under localhost conditions, median direct authenticated handshake time was 2.44 ms for ML-KEM-768 and 11.31 ms for HQC-3. Public key and ciphertext sizes were 1,184 and 1,088 bytes for ML-KEM-768, and 4,514 and 8,978 bytes for HQC-3. Canonical four-flight handshakes carried 24,762 and 35,277 bytes respectively. These historical runs included capability advertisements and both ephemeral KEM public keys.

These results are from one host. Profiles ran sequentially without fixing CPU frequency or isolating background load. Profile B and C inject delay outside the cryptographic operations, and profile C models payload serialization. All sockets stayed on localhost, with no packet loss injected. RSS was sampled and includes the Python process. These figures do not measure physical WAN behavior or peak native allocation.

## Open work

The ordered ratchet rejects future counters and recovers through a new authenticated session. Duplicate suppression covers the most recent 4,096 received logical IDs. Simultaneous new handshakes can require a retry after the handshake timeout. Physical Wi-Fi loss, Intel macOS and mobile-device browsers were outside this run. A formal state-machine model and an independent protocol and macOS endpoint review are the next research steps.
