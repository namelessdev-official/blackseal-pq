# blackseal
Offline, post-quantum message encryption terminal — runs 100% in the browser.

## Cryptography (.crypt v2)

- **KDF** — Argon2id (memory-hard, WASM via `hash-wasm`) stretches the
  passphrase into 96 bytes: a 64-byte ML-KEM keygen seed + a 32-byte key share.
- **Post-quantum KEM** — ML-KEM-1024 (FIPS 203, NIST security level 5, pure JS
  via `@noble/post-quantum`). The seed deterministically derives a keypair and a
  fresh encapsulation per message produces a 32-byte lattice shared secret.
- **Key mixing** — HKDF-SHA-512 combines the password share and the KEM shared
  secret into two independent AES-256 keys, so an attacker must defeat both
  Argon2id *and* Module-LWE.
- **Cipher** — a cascade of two AES-256-GCM layers; the entire 1646-byte header
  (including the KEM ciphertext) is authenticated as AAD by both layers.
- Legacy v1 (pre-quantum) containers remain readable.

Everything runs client-side in a web worker — no server, no accounts, no
telemetry. Build with `npm run build` to get a single self-contained HTML file
you can run air-gapped.
