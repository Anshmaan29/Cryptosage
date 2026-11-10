# Viva questions

1. **What problem does the project study?** Policy-driven post-quantum messaging and algorithm migration.
2. **What is harvest-now-decrypt-later?** An adversary stores ciphertext now, hoping future advances will reveal its contents.
3. **Why use a KEM and a signature?** The KEM establishes shared secret material. A signature authenticates the handshake and its policy choices.
4. **Why pin fingerprints?** A valid signature proves control of a key. A separately checked pin connects that key to the intended contact.
5. **What can the relay see?** Routing names, timing, packet sizes, public handshake fields and ciphertext.
6. **What can the relay do?** It can route, drop, delay, reorder or modify packets. It verifies a public registration signature.
7. **What happens if a relay name is unclaimed?** The first valid registering key owns the name until relay restart. Users must verify contact pins independently.
8. **What is crypto-agility?** The ability to select and replace cryptographic algorithms under explicit constraints.
9. **How is a KEM selected?** Both signed policies, available implementations, minimum security level, experimental opt-in and priorities determine eligibility. Comparable measurements or static library sizes resolve eligible ties.
10. **Why is HQC experimental here?** The project uses an experimental liboqs implementation and requires both policies to opt in.
11. **Why add X25519?** It supplies an independent classical contribution when both peers permit hybrid mode.
12. **What if hybrid is required by one peer and disabled by the other?** Negotiation refuses the session.
13. **How is the hybrid key derived?** The KEM and X25519 shared secrets are concatenated and processed with transcript-salted HKDF.
14. **What prevents an AEAD downgrade?** Both preference lists and the chosen cipher are in signed transcript material. Each peer independently checks the result.
15. **Which AEAD is selected?** The first cipher in the initiator's preference list that the responder also permits.
16. **Why does AES-256 remain relevant under Grover's algorithm?** Idealized quantum search offers a quadratic query advantage, leaving a large theoretical search cost. Practical cost and security depend on assumptions and implementation.
17. **How is downgrade prevention checked step by step?** Each peer verifies the pinned signing identity, checks the signed offer or response, recomputes the policy selection, checks the transcript and verifies key confirmation.
18. **What does the final acknowledgement prove?** It confirms that the responder derived the same transcript-bound confirmation key.
19. **What is forward secrecy here?** Fresh ephemeral key establishment and one-way chain advancement are intended to limit exposure of earlier session or message keys after later compromise, subject to implementation and erasure assumptions.
20. **What does it not guarantee?** It does not protect an endpoint already compromised during a session or prove that every secret copy was erased.
21. **Why is this not Signal's Double Ratchet?** This prototype has directional symmetric chains and fresh handshakes, without Signal's full ratchet, skipped-key handling and asynchronous prekey system.
22. **What happens on message replay?** A consumed counter is rejected. Persistent logical identifiers also suppress duplicate display across fresh sessions within their retention bounds.
23. **What happens on ciphertext tampering?** The AEAD integrity check rejects the message and the receive chain does not advance.
24. **What happens to out-of-order packets?** The receiver rejects a future counter. Recovery requires a fresh session and an explicit retry.
25. **What happens during re-key?** A fresh authenticated handshake establishes new chains. The previous session has a short receive grace period for in-flight messages.
26. **What does Delivered mean?** The authenticated recipient client acknowledged the consumed packet after saving it. It does not indicate that a person read it.
27. **How are local keys protected?** Supported new macOS profiles use Keychain for the local master key. Encrypted files and restrictive permissions provide additional storage controls.
28. **What is the observer?** An optional loopback page showing a bounded recent history of metadata and short ciphertext previews.
29. **What are the benchmark limits?** Results reflect a particular machine and implementation. Injected profiles model delay and bandwidth on loopback and are not physical WAN measurements.
30. **What remains to be verified?** Independent cryptographic review, formal analysis, physical multi-laptop operation and WSL execution remain open.

## Draw the handshake on the board

```text
 Alice                    untrusted relay                    Bob
   |                            |                             |
   |-- signed offer ----------->|-- offer ------------------->|
   |   policies, KEM keys, optional X25519                   |
   |                            |<-- signed response ---------|
   |<-- response ---------------|   selected KEM/AEAD,        |
   |                            |   ciphertext, confirmation |
   |-- finish confirmation ---->|-- finish ------------------>|
   |                            |<-- acknowledgement ---------|
   |<-- acknowledgement --------|                             |
   |                            |                             |
   |==== directional encrypted messages and receipts ========|
```
