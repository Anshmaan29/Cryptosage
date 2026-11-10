# Presentation outline

1. **Title and team** — Show the project title and contributor placeholders. Say the project is a research prototype for policy-driven post-quantum messaging.
2. **Problem** — Show a harvest-now-decrypt-later timeline. Explain why stored ciphertext and long confidentiality lifetimes motivate migration.
3. **Objectives** — Show the objectives diagram. Describe authentication, policy-driven negotiation, encrypted delivery and measurable evaluation.
4. **Architecture** — Show the Mermaid architecture from the README. Trace endpoint plaintext and relay-visible metadata.
5. **Protocol** — Show the handshake diagram. Explain signatures, transcript binding and mutual key confirmation.
6. **Selection engine** — Show the selection inspector. Explain policy gates, experimental opt-in, priority and measured or static-size tie breaks.
7. **Security features** — Show the identity verification dialog. Explain fingerprint pinning, hybrid agreement, AEAD and directional chains.
8. **Attack demonstration** — Show the recorded attack result. Describe the attempted modification and the validation observed, including the experiment's scope.
9. **Results** — Show the localhost handshake distribution and results table. State the machine, sample size and benchmark limitations from the recorded JSON.
10. **Relay view** — Show the observer after sending a message. Identify visible routing metadata and ciphertext preview.
11. **Limitations** — Show the threat-boundary diagram. Discuss first-seen registration, ordered delivery, endpoint compromise and lack of independent protocol review.
12. **Future work** — Show a short roadmap. Discuss review, formal analysis, physical-network experiments and multiple simultaneous conversations.
13. **Conclusion** — Show the architecture again. Summarize the demonstrated functionality and invite questions.
