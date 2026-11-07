# Threat model and limitations

## Intended demonstration

Crytosage demonstrates policy-based KEM selection, contact authentication, transcript integrity, authenticated key establishment, directional message-key evolution, attack rejection, and reproducible evaluation. The prototype assumes that the two endpoint machines, their Python clients, and their local browsers are trusted. Users compare identity fingerprints through a trusted channel before pinning them.

An attacker may control the relay and network traffic, introduce its own identities, supply malformed packets, and replay recorded packets. The protocol treats capability lists, selected identifiers, identity keys, and ciphertexts as untrusted until validation succeeds.

| Attempt | Relevant check | Limit |
| --- | --- | --- |
| Edit capability list or selected KEM | ML-DSA signatures, offer hash, independently recomputed policy selection | A trusted malicious endpoint can refuse to connect |
| Substitute a key under a known contact name | Explicit fingerprint pin | Users must compare fingerprints correctly |
| Introduce a new signed identity | Unknown contacts rejected until pinned | A signature proves key possession, not a human identity |
| Replay a handshake | Fresh session/nonce, timestamp, replay cache, transcript-bound confirmations | Cache is bounded and in memory; availability is not guaranteed |
| Replay a chat message | Session identifier and expected directional counter | Old session state is discarded on reconnect |
| Modify ciphertext or authenticated header | AES-GCM tag, strict envelope/counter validation | Invalid traffic can still consume processing time |
| Send invalid key/ciphertext sizes | Adapter validation before native operations | Correct-size KEM corruption can use implicit rejection; confirmation rejects the wrong secret |
| Invoke local APIs from another website | Loopback binding, Host/Origin/Fetch Metadata checks and application token | A malicious local user process is outside this boundary |

## Storage and endpoint exposure

Identity secrets and conversation history are stored in AES-GCM envelopes. The default random local master key is stored in a mode-0600 file inside a private directory: copying the whole directory or compromising the account exposes it. Setting CRYTOSAGE_STORAGE_PASSWORD before creating identities derives the key with scrypt; keep the password securely and use the same setting on every launch. Existing storage cannot be switched by merely changing this variable. The demonstration's public-contact directory contains public keys only and does not authorize trust automatically.

The local browser and client process see plaintext. Encrypted conversation history persists locally; session and ratchet chains are not persisted and a new handshake is needed after restart. Secret fields are excluded from public state and the dashboard, but Python immutable byte objects can leave copies in memory. Garbage collection does not provide verifiable secure erasure, and deleting a variable does not prove its bytes were overwritten.

Keep test identities separate from any real identity. Do not publish `.runtime/`, `.venv/`, `.local/`, or build caches. The Git ignore file excludes these generated directories.

## Ratchet guarantees

Separate directional chains and explicit derivation domains prevent using the same message key in both directions. A consumed message advances its chain. Compromise of the current chain should not reveal prior chain values under the one-way derivation assumption, but this is not a formal proof of the complete Python implementation or its memory behavior.

The symmetric chain has no new entropy between post-quantum re-keys. Compromise of a current sending or receiving chain can expose future keys in that direction until a fresh, uncompromised KEM handshake. It does not provide Signal's Double Ratchet, skipped-key handling, asynchronous prekeys, or a general post-compromise security guarantee. The optional X25519 hybrid mode is not implemented.

## Protocol and operational limits

- The custom handshake has not received independent expert review or formal verification. Passing tests cover the specific executions and assertions recorded in the reports.
- ML-KEM-768 and ML-DSA-65 use the pinned library implementations. Library bugs, supply-chain failures, side channels, randomness failure, and endpoint compromise remain risks.
- HQC-3 is experimental in this liboqs build. Both policies must opt in before selection, and the normal session policy prefers ML-KEM-768.
- The relay observes metadata, traffic volume, and timing. There is no padding, anonymity, traffic-analysis resistance, or availability protection.
- The research demo uses loopback HTTP and WebSockets. Deploying it on a public network requires a separate design for transport security, endpoint isolation, authentication, rate limits, and service operations.
- A trusted peer can initiate costly handshakes, send unexpected traffic, or stop participating. The bounded replay cache and packet sizes do not constitute a complete denial-of-service defense.
- The ordered ratchet rejects future counters. It has no durable queue, offline delivery, or reliable delivery acknowledgement at the application layer. The UI's sent state means the local client submitted an encrypted packet, not that the peer read it.
- Connections may reconnect to the relay, but a new authenticated session is required after a disconnection. Session keys are not saved for reuse after process restarts.
- Secret identity changes require explicit offline investigation and trust reset. There is no production account recovery, revocation service, or certificate authority.

## Future work

Useful research extensions include an independently reviewed protocol specification, formal state-machine analysis, tighter native secret handling, continuous native-memory profiling, transport-aware benchmark decomposition, bounded skipped-message handling, independent review of authenticated delivery receipts, and a reviewed hybrid key combiner. These changes require their own security analysis rather than adding feature flags to the current guarantees.
