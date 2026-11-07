# Crytosage development

Use Ponytail for coding work. Read relevant installed UI skills (Hallmark, Impeccable, UI UX Pro Max), Humanizer for prose, and gstack review/QA skills when applicable. Do not install or use Onyx. A missing skill does not justify inventing its instructions.

This is a research prototype, never production-certified. Keep cryptography real: liboqs ML-KEM-768/HQC-3 and ML-DSA-65, AES-256-GCM and HKDF from cryptography. Never replace unavailable algorithms or fabricate measurements, successful attacks, or passing tests. HQC-3 remains experimental by default.

Preserve the relay/client boundary: server and relay mutation helpers may only route/modify opaque envelopes; no private-key operations, session derivation, or plaintext there. Local browser APIs must retain loopback Host/Origin checks, CSRF protection, and explicit recipient/session binding. Do not expose .runtime/ or private keys.

Use the existing checkout; cloud tasks are already isolated. Do not create a worktree unless requested.

Setup: `bash scripts/setup.sh`. Run: `bash scripts/run_demo.sh`. Evaluate: `.venv/bin/python -m scripts.evaluate`. Benchmark: `.venv/bin/python -m scripts.benchmark --trials 30`. Browser smoke requires the real demo and Playwright; see docs/EVALUATION.md. Update reports after material changes and keep unavailable/unrun checks explicit.
