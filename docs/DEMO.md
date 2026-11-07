# Demonstration and viva

## A reproducible demonstration

1. Run `bash scripts/run_demo.sh`, then open Alice's port 8001 and Bob's port 8002 locally.
2. Show that both clients connect to the relay while the session remains unestablished.
3. Compare fingerprints through the two trusted local screens. Pin each contact explicitly. Explain why an unknown valid signature is insufficient.
4. Establish from one client. Show ML-KEM-768, the policy decision reason, peer-verification state, and real handshake time.
5. Exchange a message in each direction. Show independent directional counters and local encryption/decryption measurements. No plaintext or key appears on the relay's routing interface.
6. Renew session keys. Show a new session identifier and reset message counters after a fresh signed handshake.
7. Open **Security lab → Attack lab**. Run each isolated experiment and read its actual reason. Explain the difference between a signature failure, identity pin mismatch, replay rejection, invalid length, and AEAD failure.
8. Run ten benchmark trials in the UI, or run thirty through the CLI. Compare ML-KEM-768 with HQC-3 at level 3. Identify the experimental status and the limits of local memory/timing measurements.
9. Run the automated evaluation and inspect the newly written report. Retain failures if any appear.
10. Stop and restart a client. Its identity and pins persist; its encrypted message history persists while its old live session does not. Establish a new session.

For a policy demonstration, use the examples in [Policy](POLICY.md) to prohibit an algorithm or require an unavailable security level. Both clients must refuse the resulting unacceptable session. Restore the normal policy for the rest of the demonstration.

## Concise viva explanation

**What problem does the project study?** It studies whether two messaging clients can negotiate a permitted post-quantum KEM automatically while authenticating the negotiation, rejecting downgrade attempts, and measuring the real implementation.

**Why a KEM and a signature?** A KEM establishes a shared secret. ML-DSA signatures authenticate the negotiation under a pinned contact key. KEM establishment alone does not prove which contact participated.

**What makes the selection policy driven?** JSON files define level requirements, prohibited/experimental status, priorities and measured preferences. Both signed policies constrain a deterministic selection. A faster algorithm cannot bypass a security requirement.

**Why verify fingerprints?** A signature from a stranger proves control of that stranger's key. A fingerprint compared over a trusted channel associates the expected contact with the public key. Later substitutions fail the stored pin.

**Why authenticate the transcript?** Changing an offered algorithm, key, identity, nonce, session identifier or selection must invalidate authentication or the derived confirmations. Both sides recompute selection rather than trusting the relay's claim.

**Why use HKDF?** Domain-separated HKDF derivations turn the KEM secret into purpose-specific confirmation, root, directional-chain and message keys, bound to the transcript.

**How is nonce reuse prevented?** Every direction has a separate evolving chain. Each message uses a derived key and a counter nonce; the counter advances, and fresh sessions derive new chains. The receiver rejects consumed counters.

**Is this Signal?** No. It has a directional symmetric ratchet and fresh authenticated post-quantum re-keys. It lacks Signal's full Double Ratchet, asynchronous prekeys and skipped-message-key handling.

**What can the relay do?** It can observe metadata, deny service and alter packets. It has no endpoint secrets or plaintext through this protocol. The tests demonstrate selected integrity, identity and replay checks; they do not prove every possible attack is prevented.

**What does HQC-3 mean?** It is the actual current liboqs level-3 identifier in this build. The earlier requested HQC-192 identifier is not silently aliased. HQC-3 remains experimental here and requires both policies' opt-in.

**What do the benchmarks prove?** They measure this build on the recorded machine under the recorded conditions. They support performance comparison, not a ranking of cryptographic strength or a claim about remote-network latency.

**What remains before production use?** Independent protocol review, formal analysis, stronger endpoint/key handling, operational hardening and a separate deployment design. This university prototype is not production certified.
