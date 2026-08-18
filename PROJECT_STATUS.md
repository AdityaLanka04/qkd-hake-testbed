# Hybrid QKD-PQC HAKE Testbed — Project Status

## Project Brief

**Title**: Hybrid QKD-PQC Authenticated Key Exchange without Digital Signatures

### Problem Statement
Hybrid key exchange runs QKD and post-quantum cryptography (PQC) side by side, so that a break in either does not compromise the session. Recent work has gone further, dropping digital signatures entirely and using Key Encapsulation Mechanisms (KEMs) to authenticate instead.

However, every hybrid QKD-PQC protocol proposed so far—including the Clermont-Henrich 2026 signature-free design this project builds on—assumes that QKD key material is readily available whenever a handshake requires it. Real links do not operate this way. A typical metro QKD link produces a few kilobits per second, whereas each handshake consumes a fresh 256-bit key. At 10 kbps, this yields roughly 39 handshakes per second before the store runs dry. 

When starvation occurs, the protocol does not throw an error; instead, it quietly falls back to computational-only security and still reports a successful handshake. This silent downgrade strips away the information-theoretic security guarantee without notifying upstream systems. Nobody has measured where that ceiling sits or evaluated the costs of defending against it. This project fills that gap.

### Primary Objectives
1. **Mock QKD 014 Server**: Build a small ETSI GS QKD 014 mock server containing an in-memory key pool with a configurable refill rate/depth, exposing `GetKey` and `GetKeyWithIDs` so both sides can pull the same key by ID.
2. **Signature-Free HAKE Design**: Design and specify a signature-free HAKE that mixes a long-term KEM for authentication, an ephemeral KEM for forward secrecy, and a QKD key, all through a labelled HKDF-SHA3-256 chain, confirmed with a MAC over the transcript.
3. **Implementation & Baselines**: Implement the protocol, build a pure-PQC baseline for comparison, and benchmark both across ML-KEM-512/768/1024 and FrodoKEM-976-AES for latency, CPU time, and bytes on the wire (reporting median and 95th percentile over 1000 runs).
4. **Key Starvation Sweeps**: Sweep handshake rates (1/5/10/20/50/100 per second) against QKD supply (1/10/100 kbps), logging latency and pool occupancy to plot the knee where the key store, rather than the cryptography, becomes the bottleneck.
5. **Mitigations Implementation**: Implement and measure the cost of three fixes for key starvation: per-peer quotas, admission control that refuses handshakes instead of degrading, and an explicit signal that the session has dropped to computational-only security.
6. **Security Analysis**: Write a modular security analysis including a compromise matrix over four failure cases (nothing broken, QKD broken, KEM broken, both broken) against three properties, plus a CK01 game-hop outline.

### Expected Deliverables
* **HAKE Testbed**: A working, reproducible signature-free HAKE testbed (Python, liboqs-python, mock ETSI GS QKD 014 key server), released as open-source scripts with a one-command reproduction path.
* **starvation Metrics**: The first measurement of how a finite QKD key supply bounds handshake throughput, and a proper account of the silent downgrade from information-theoretic to computational-only security under load.
* **Operational Recommendation**: A practical answer to whether per-peer quotas and admission control are sufficient to preserve information-theoretic security at realistic key rates, or if QKD-backed key exchange is restricted to low-session-rate links.

---

## What Has Been Completed

### 1. Project Infrastructure & Development Setup
* Established the Python project structure using `pyproject.toml` and standard virtual environment setups.
* Configured automated developer flows with a `Makefile` supporting setup, unit testing, running the API server, and executing local demos.

### 2. Mock ETSI GS QKD 014 Key Management Entity (KME)
* Implemented an in-memory QKD key pool supporting configurable key size, pool depth, refill rate, and peer quotas.
* Exposed ETSI GS QKD 014-style HTTP API endpoints:
  * `Get status`
  * `Get key` (encryption key retrieval)
  * `Get key with key IDs` (decryption key retrieval)
* Added identification of source/destination Secure Application Entities (SAEs) via custom HTTP headers (`X-SAE-ID`).
* Implemented error handling for missing SAE identity, pool exhaustion, exceeded quotas, and invalid/reused key IDs.

### 3. Cryptographic Primitives & KDFs
* Wrapped `liboqs-python` to interface with ML-KEM-512, ML-KEM-768, ML-KEM-1024, and FrodoKEM-976-AES.
* Developed a robust Multi-Input Key Derivation Function (ROKDF) utilizing SHA-3-512 and HMAC-SHA-256 for key derivation and session confirmation tags.
* Designed explicitly separated security states (`HYBRID_QKD`, `PQC_ONLY`, `REJECTED`) to avoid silent downgrades when QKD key pools are exhausted.

### 4. Protocol Pipeline & Mitigations
* Implemented the Clermont-Henrich 2026 Signature-Free HAKE 4-message exchange protocol between Alice (client) and Bob (server).
* Implemented active starvation mitigations:
  * **Quota limits**: Restricting outstanding keys per peer.
  * **Admission Control**: Reserving keys for higher-priority transactions or rejecting hybrid handshakes when pool occupancy falls below a 5% threshold.
  * **PQC Fallback**: Graceful fallback to `PQC_ONLY` mode when QKD keys are unavailable, if allowed by policy.

### 5. Benchmarking & Analysis
* Built a benchmarking framework to run performance and starvation sweeps over different handshake/supply rates and KEM algorithms.
* Authored the CK01 model game-hop security analysis and compromise matrix in [docs/security_analysis.md](file:///c:/Users/Abishek/quantum/qkd-hake-testbed/docs/security_analysis.md).
* Developed 17 automated unit and integration tests covering the key pool, combiner, KEM operations, and full HAKE handshakes.

---

## What Needs to Be Done (Next Steps)

* **Docker Support**: Containerize the mock KME server and benchmark harness to allow simple, single-command reproduction of experiments.
* **Continuous Integration**: Create a GitHub Actions workflow to run the suite of 17 tests automatically on code changes.
* **Documentation & Examples**: Expand user guide docs and draft additional step-by-step usage examples for using the API.
* **Safety Disclaimers**: Add explicit warnings across the repository indicating that the code is an experimental research testbed and is not suitable for securing production traffic.
