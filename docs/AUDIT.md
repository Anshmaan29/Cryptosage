# V1 audit and V2 evidence

The pre-change V1 run completed 142 tests. Live tests established independent Python clients over a local WebSocket relay and exercised messages, re-keying, replay, tampering, and reconnection. Direct liboqs operations verified ML-KEM-768, HQC-3 and ML-DSA-65; the relay module routes envelopes and does not import cryptography or client key material. These observations are not a proof of protocol security.

The V1 audit identified unconfirmed delivery status, memory-only history, plaintext identity files protected by filesystem permissions, and a missing reconnect control when history existed. V2 adds authenticated delivery receipts, encrypted history and identity files, an explicit reconnect control and policy constraints for new sessions. The default master key remains accessible to the same user or anyone with a copy of the complete data directory.

V2 laboratory results are isolated experiments and not attacks against the active conversation. Benchmarks disclose loopback timing and resource limitations. The protocol event page currently shows recorded client events; it does not record every internal cryptographic step. The guided demo is a checklist, not an automated end-to-end orchestrator. Delivery confirmation means the receiving client authenticated and stored the message, not that a person read it. A resend can duplicate a message whose receipt was lost.

Linux x86-64 was tested in this cloud environment. macOS and Apple Silicon are documented but were not available for testing. Python cannot guarantee secret erasure. This custom research protocol has no formal proof or independent cryptographic review and must not be used for sensitive communications.
