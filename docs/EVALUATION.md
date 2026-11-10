# Evaluation

## Automated tests

Run the current suite and generate the current security report from the repository root:

```sh
.venv/bin/python -m pip install -r requirements-dev.txt
CRYTOSAGE_REPORT_DIR=reports/macos-v3 ./scripts/run_tests.sh \
  --cov=crypto --cov=protocol --cov=policy --cov=client --cov=server --cov=attacks \
  --cov-report=xml:reports/macos-v3/coverage.xml --cov-report=html:reports/macos-v3/coverage-html
```

The report records observed runner outcomes. A passing test confirms its stated assertions on that run. Failures, skipped checks, and collection errors must remain visible. Reports from earlier revisions do not establish that a later change passed.

The suites exercise actual liboqs ML-KEM-768/HQC-3 operations, ML-DSA-65 verification, AEAD, policy selection, explicit identity pins, signed transcript integrity, key confirmations, replay counters, corrupted inputs, and ratchet state. Network/API tests check the surrounding client/relay boundaries where included by the current runner.

The attack lab uses the same protocol implementation as the messenger. Each experiment creates fresh temporary identities, explicitly pins the known test public keys, establishes any required real session, mutates the chosen packet, and records the actual exception or acceptance. An attack is reported blocked only when its attempted operation is rejected. An unexpected acceptance is a failed security result.

| Scenario | Mutation | Expected observation |
| --- | --- | --- |
| Algorithm downgrade | Change the authenticated selection or capabilities | Negotiation signature/transcript or policy rejection |
| Identity substitution | Replace identity with an attacker's genuinely signed key | Pinned identity mismatch |
| Replay | Re-submit a consumed encrypted packet | Consumed message-counter rejection |
| Ciphertext tampering | Flip a ciphertext byte | GCM integrity failure; plaintext withheld |
| Invalid input | Submit a malformed KEM key under a controlled endpoint signature | Length/cryptographic-input validation failure |

The invalid-input lab deliberately signs the malformed input using the known lab endpoint. This lets it test the adapter validation that a relay-only mutation may never reach because the altered signature fails first. The distinction appears in the actual rejection reason.

For a one-shot live relay experiment, stop the normal relay and restart it with an explicit developer switch:

```sh
.venv/bin/python -m server.relay --attack tamper
```

Supported names are `downgrade`, `identity`, `replay`, `tamper`, and `invalid`. The relay applies its selected mutation to eligible traffic. Reconnect the clients and establish a fresh session after an experiment as needed. Keep these switches limited to this project's local test environment.

## Benchmarks

```sh
./scripts/run_benchmarks.sh --trials 100 --profile localhost --output reports/macos-localhost
./scripts/run_benchmarks.sh --trials 30 --profile moderate --output reports/macos-moderate
./scripts/run_benchmarks.sh --trials 30 --profile constrained --output reports/macos-constrained
```

Profile A adds no delay. Profile B injects 25 ms before each endpoint send. Profile C injects 100 ms before each send and adds payload serialization time at a modeled 256 kb/s. The WebSocket connection stays on localhost throughout. These profiles do not inject packet loss, limit real interface throughput, or change the independent cryptographic-computation timers.

The full-protocol wrapper supplies an adapter that creates independently pinned identities, completes all four handshake flights, sends an authenticated encrypted ping and pong, and measures the real work. A separate per-trial loopback WebSocket relay measures the protocol over real sockets and a fixed opaque transport round trip. Identity creation and relay startup are outside the handshake timing. The lower-level `python -m benchmarks.runner` command measures primitive KEM computation without that adapter and labels full-handshake measurements unavailable.

Measurements include key generation, encapsulation, decapsulation, public-key and ciphertext lengths, malformed input behavior, selection overhead, and, when the full adapter is supplied, complete authenticated handshake time/bytes and message timings. Repeated trials report mean, median, sample standard deviation, nearest-rank P95, minimum and maximum. Reports preserve raw trials and identify library versions, CPU, OS, Python, timer and sample count.

`reports/` contains actual JSON and CSV outputs plus matplotlib PNG/SVG graphs. A missing or disabled algorithm stays marked unavailable. Computation and loopback transport columns remain separate. Neither KEM-only timing nor direct protocol timing is described as network transmission latency.

## Measurement limits

- Primitive timers use `time.perf_counter_ns`. CPU uses process CPU time; concurrent threads can affect it, and CPU percentage may exceed 100%.
- RSS is sampled around operations. It can miss a short native allocation spike. Process high-water RSS is cumulative and cannot attribute a prior peak to the current trial.
- `tracemalloc` reports Python allocation peaks, not all native liboqs allocations. None of these is a continuous peak-native-memory profiler.
- Full handshake byte counts include canonical protocol envelopes, both advertised policies/profiles, signatures, public keys, confirmations and ciphertext. They exclude WebSocket/TCP/IP framing.
- The initiator generates keys only for KEMs admitted by its own policy. The benchmark restricts each run to the KEM under test.
- `handshake_ms` and `message_roundtrip_ms` are direct protocol-computation measurements. `network_handshake_ms` measures the full handshake through a real loopback relay, including computation, serialization and socket scheduling. It is not pure transmission time.
- `network_message_roundtrip_ms` starts after the first message is encrypted. It includes outbound delivery, peer decryption, reply encryption, return delivery and reply decryption. The initial encryption is measured separately. `relay_transport_roundtrip_ms` measures a fixed 4096-character opaque payload and routing envelopes without cryptographic work; its payload differs from a chat packet, so subtracting it does not isolate exact protocol overhead.
- Loopback timings do not establish LAN or WAN behavior. Browser-to-local-client HTTP latency is not measured by these protocol benchmarks. Client dashboard handshake timers observe their respective local intervals; responder and initiator timers do not start at exactly the same point.
- Small samples, CPU scaling, competing processes and build choices affect results. Compare equivalent security levels and preserve test conditions. Faster timing does not imply stronger security.
