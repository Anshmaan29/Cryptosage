# Threat model and limitations

## Intended demonstration

Cryptosage demonstrates policy-based KEM selection, contact authentication, transcript integrity, authenticated key establishment, directional message-key evolution, attack rejection, and reproducible evaluation. The prototype assumes that the two endpoint machines, their Python clients, and their local browsers are trusted. Users compare identity fingerprints through a trusted channel before pinning them.

An attacker may control the relay and network traffic, introduce its own identities, supply malformed packets, and replay recorded packets. The protocol treats capability lists, selected identifiers, identity keys, and ciphertexts as untrusted until validation succeeds.

The native relay verifies one public ML-DSA-65 possession proof at registration. It binds a name to the first verified key fingerprint until the relay restarts. The challenge is fresh per connection. This limits replacement after first registration. It cannot establish who should own a previously unseen name. Clients still authenticate their contacts independently. The relay has no private key, session key or plaintext.

| Attempt | Relevant check | Limit |
| --- | --- | --- |
| Edit capability list, X25519 key, selected KEM, hybrid mode or AEAD | ML-DSA signatures, offer hash, independently recomputed policy selection | A trusted malicious endpoint can refuse to connect |
| Substitute a key under a known contact name | Explicit fingerprint pin | Users must compare fingerprints correctly |
| Introduce a new signed identity | Unknown contacts rejected until pinned | A signature proves key possession, not a human identity |
| Replay a handshake | Fresh session/nonce, timestamp, replay cache, transcript-bound confirmations | Cache is bounded and in memory; availability is not guaranteed |
| Replay a chat message | Session identifier and expected directional counter | Old session state is discarded on reconnect |
| Modify ciphertext or authenticated header | Negotiated AEAD tag, strict envelope/counter validation | Invalid traffic can still consume processing time |
| Send invalid key/ciphertext sizes | Adapter validation before native operations | Correct-size KEM corruption can use implicit rejection; confirmation rejects the wrong secret |
| Invoke local APIs from another website | Loopback binding, Host/Origin/Fetch Metadata checks and application token | A malicious local user process is outside this boundary |

## Storage and endpoint exposure

Identity secrets, conversation history and duplicate records use AES-256-GCM envelopes. New macOS profiles use the local file-based Keychain through Security.framework. An access denial, missing item or key mismatch stops profile access. Profiles use a private directory and mode-0600 private files. Contact pins persist separately and require the independently verified replacement fingerprint plus explicit confirmation of the previous pin. Keychain reduces exposure from copying the application directory. A compromised account, browser or process that can read the unlocked key or plaintext remains outside this boundary.

To migrate an existing filesystem-backed profile, stop the client and securely back up the profile first. Use the command below once per profile.

```sh
.venv/bin/python -m scripts.init_demo --root .runtime --name Alice --migrate-to-keychain
```

Migration reads the encrypted identity and history with the existing key, creates or verifies the Keychain item, then atomically changes the backend selector. The identity, history and pin files keep their original bytes. An interruption before the selector changes leaves filesystem mode active and the command can be rerun. The original `.keystore/master.key` remains beside the data for recovery. The copied-directory threat persists while that file is there. After verifying the migrated profile opens and an independent recovery copy is available, move the legacy key to separate protected backup storage if you choose.

For a fresh profile on a Mac without accessible Keychain, set `CRYTOSAGE_STORAGE_PASSWORD` securely before first launch and supply the same password on later launches. This mode derives the key using scrypt. An explicit `CRYTOSAGE_STORAGE_BACKEND=filesystem` is also available for a fresh profile. Its key relies on local permissions and remains readable to an attacker who obtains the entire profile. A failed Keychain profile keeps its configured mode. Use a separate fresh profile for fallback or restore access to the original item.

The local client and browser see plaintext. Live session keys stay in memory. Python cannot guarantee the erasure of immutable secret bytes. Use separate test identities and keep private profiles, keys and build logs out of public bundles.

## Ratchet guarantees

Separate directional chains and explicit derivation domains prevent using the same message key in both directions. A consumed message advances its chain. Compromise of the current chain should not reveal prior chain values under the one-way derivation assumption, but this is not a formal proof of the complete Python implementation or its memory behavior.

The symmetric chain has no new entropy between post-quantum re-keys. Compromise of a current sending or receiving chain can expose future keys in that direction until a fresh, uncompromised KEM handshake. It does not provide Signal's Double Ratchet, skipped-key handling, asynchronous prekeys, or a general post-compromise security guarantee. Native hybrid sessions combine independent ephemeral KEM and X25519 outputs with transcript-salted HKDF. X25519 adds a classical component. The custom combination and overall protocol have not been independently reviewed.

## Protocol and operational limits

- The custom handshake has not received independent expert review or formal verification. Passing tests cover the specific executions and assertions recorded in the reports.
- The ML-KEM family and ML-DSA-65 use the pinned library implementations. Library bugs, supply-chain failures, side channels, randomness failure, and endpoint compromise remain risks.
- HQC is experimental in this liboqs build. Both policies must opt in before selection. The default policy prefers recommended ML-KEM algorithms.
- The relay observes metadata, traffic volume, and timing. There is no padding, anonymity, traffic-analysis resistance, or availability protection.
- The research demo defaults to loopback HTTP and WebSockets. The optional LAN relay uses plaintext WebSocket transport, so observers can see routing metadata, handshake public fields and ciphertext. The relay metadata page is loopback-only and in memory. Deploying it on a public network requires a separate design for transport security, endpoint isolation, authentication, rate limits, and service operations.
- A trusted peer can initiate costly handshakes, send unexpected traffic, or stop participating. The bounded replay cache and packet sizes do not constitute a complete denial-of-service defense.
- The ordered ratchet rejects future counters. A dropped packet can require a new session and an explicit retry. Duplicate suppression is bounded to 4,096 distinct received IDs, and can be lost after eviction or rollback. A receipt demonstrates authenticated client storage rather than human readership.
- Connections may reconnect to the relay, but a new authenticated session is required after a disconnection. Session keys are not saved for reuse after process restarts.
- Secret identity changes require explicit offline investigation and trust reset. There is no production account recovery, revocation service, or certificate authority.

## Future work

Useful research extensions include an independently reviewed protocol specification, formal state-machine analysis, tighter native secret handling, continuous native-memory profiling, transport-aware benchmark decomposition, bounded skipped-message handling, independent review of authenticated delivery receipts, and expert review of the hybrid key combiner. These changes require their own security analysis rather than adding feature flags to the current guarantees.

Multiple simultaneous conversations are future work. The current client maintains one active session at a time.

## Negotiation and observer review

The native `crytosage/3` offer and response authenticate the hybrid public keys, policies, selected KEM and AEAD. The message header also authenticates the selected AEAD. Hybrid mode combines independently generated KEM and X25519 secrets using transcript-salted HKDF. This custom construction requires independent review.

The optional relay observer is read-only and loopback-bound. It stores bounded metadata and ciphertext previews in memory. Its display reflects fields provided to the relay and does not authenticate their semantic meaning.
