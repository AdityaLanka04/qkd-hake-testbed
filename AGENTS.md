# Codex instructions for this repository

## Project purpose

This repository is a research testbed for a signature-free hybrid QKD-PQC
authenticated key exchange. Its main contribution is measuring QKD key-pool
starvation and evaluating quota, admission-control, and explicit-downgrade
policies.

## Working rules

- Treat this as experimental research software, not production cryptography.
- Do not describe a locally invented handshake as the paper's exact protocol.
  Match message ordering, labels, and security assumptions against the cited
  2026 HAKE paper before claiming protocol compatibility.
- A missing QKD key must never silently become an empty byte string or zero key.
  Return `PQC_ONLY` explicitly or reject the handshake.
- Bind the negotiated security mode, algorithm name, roles, nonces, public
  keys, ciphertexts, and QKD key ID into the transcript.
- Keep benchmark setup, warm-up count, random seeds, host details, and raw CSV
  output reproducible.
- Never log secret keys, shared secrets, QKD key bytes, or derived session keys.
- Use type hints and small testable modules.

## Commands

- Install: `make setup`
- Run tests: `make test`
- Start mock KME: `make server`
- Run the local smoke demo: `make demo`

## Implementation order

1. Finish and test the ETSI GS QKD 014 mock API.
2. Transcribe the paper's exact HAKE message flow into `protocol/`.
3. Add ML-KEM and FrodoKEM through liboqs-python.
4. Add the pure-PQC baseline using the same transport and measurement hooks.
5. Add rate sweeps and starvation policies.
6. Generate plots and security-analysis tables from recorded results.

## Verification

Run `make test` after every behavioral change. Add a regression test whenever
fixing pool accounting, key-ID retrieval, downgrade signaling, transcript
binding, or benchmark measurement.
