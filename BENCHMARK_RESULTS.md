# Hybrid QKD-PQC HAKE Testbed — Benchmarks and Test Results

This document summarizes the performance evaluation, message size measurements, and test suite verification results for the Hybrid QKD-PQC Authenticated Key Exchange (HAKE) testbed.

---

## 1. Automated Test Suite Verification

The project includes a comprehensive set of unit and integration tests to verify the correctness of the cryptographic primitives, the mock QKD Key Management Entity (KME), and the Clermont-Henrich 2026 4-message handshake pipeline.

* **Total Tests**: 17 tests
* **Status**: 17 Passed
* **Execution Time**: 1.13 seconds

### Key Areas Tested:
1. **QKD Key Generation & Synchronization**: Verification that both Secure Application Entities (SAEs, Alice & Bob) receive the identical 256-bit key from the KME using one-time UUID-based retrieval.
2. **QKD Pool Operations**: Testing pool capacity exhaustion, refill rates, and per-peer quota limits.
3. **KDF & Combiner**: Correct derivation of session keys and confirmation tags using labelled HKDF/ROKDF chains, ensuring zero silent downgrades.
4. **HAKE Handshake Execution**: Execution of the Clermont-Henrich 2026 protocol under full hybrid (`HYBRID_QKD`), fallback (`PQC_ONLY`), and strict (`REJECTED`) states.

---

## 2. Performance Benchmarking

A performance suite was run over **1,000 handshake runs** to compare the hybrid QKD-PQC protocol execution against a classical, post-quantum-only (`PURE_PQC`) baseline. The benchmark covers two main families of KEMs: Module Lattice-based KEMs (ML-KEM) and Unstructured Lattice-based KEMs (FrodoKEM).

### Benchmark Results Table (1,000 Runs)

| Algorithm | Handshake Mode | Median Latency | 95th Percentile Latency | Message Size on Wire |
| :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | HYBRID | 0.413 ms | 0.499 ms | 3,253 bytes |
| | PURE_PQC | 0.404 ms | 0.433 ms | 3,232 bytes |
| **ML-KEM-768** | HYBRID | 0.559 ms | 0.645 ms | 4,597 bytes |
| | PURE_PQC | 0.551 ms | 0.669 ms | 4,576 bytes |
| **ML-KEM-1024** | HYBRID | 0.730 ms | 0.858 ms | 6,421 bytes |
| | PURE_PQC | 0.722 ms | 0.834 ms | 6,400 bytes |
| **FrodoKEM-976-AES** | HYBRID | 10.334 ms | 11.305 ms | 63,013 bytes |
| | PURE_PQC | 10.432 ms | 11.680 ms | 62,992 bytes |

---

## 3. Key Starvation & Bottleneck Sweep Analysis (Addressing the Gap)

A primary objective of this project is to measure what happens when finite QKD resources are depleted by client handshake requests—specifically, to quantify the "silent downgrade" threshold where the protocol falls back from information-theoretic hybrid security to computational-only (`PQC_ONLY`) security.

To address this, we simulated handshake request rates (1 to 100 req/s) against typical metropolitan QKD key generation rates (1, 10, and 100 kbps) for 10-second intervals.

### Bottleneck Sweep Results Table

| QKD Supply Rate | Handshake Rate | Success Rate (Hybrid Mode) | Final Pool Occupancy | Starvation Status |
| :--- | :--- | :--- | :--- | :--- |
| **1 kbps** | 1 req/s | 100.0% | 99.2% | NO |
| | 5 req/s | 100.0% | 91.4% | NO |
| | 10 req/s | 100.0% | 52.3% | NO |
| | **20 req/s (Knee)** | **83.5%** | **0.0%** | **YES (Starved)** |
| | 50 req/s | 33.4% | 0.0% | YES (Starved) |
| | 100 req/s | 16.7% | 0.0% | YES (Starved) |
| **10 kbps** | 1 req/s | 100.0% | 99.2% | NO |
| | 5 req/s | 100.0% | 99.2% | NO |
| | 10 req/s | 100.0% | 99.2% | NO |
| | 20 req/s | 100.0% | 99.2% | NO |
| | 50 req/s | 100.0% | 14.1% | NO |
| | **100 req/s (Knee)**| **51.8%** | **0.0%** | **YES (Starved)** |
| **100 kbps** | 1 to 100 req/s | 100.0% | 99.2% | NO |

---

## 4. Analysis & Key Takeaways

### A. ML-KEM vs. FrodoKEM Latency
* **ML-KEM (Structured Lattices)** provides exceptionally fast handshakes, all executing in **under 1 millisecond** (median latency $0.4\text{ ms} - 0.7\text{ ms}$). This makes ML-KEM highly practical for low-latency production applications.
* **FrodoKEM-976-AES (Unstructured Lattices)** introduces significant computation times, requiring around **10 to 11 milliseconds** per handshake (~25 times slower than ML-KEM). This latency is a direct consequence of the large-dimensional matrix calculations required by FrodoKEM's conservative security model.

### B. Bandwidth on the Wire
* **ML-KEM** keeps payloads lightweight, consuming **~3.2 KB to ~6.4 KB** of bandwidth across all handshake messages.
* **FrodoKEM** requires a massive **~63 KB** payload, which creates substantial network traffic. This heavy footprint can lead to packet fragmentation and increased packet loss on low-bandwidth or unreliable networks.

### C. Hybrid QKD-PQC Protocol Overhead
* **Computational Overhead**: The latency overhead of running `HYBRID` mode over `PURE_PQC` is negligible—measuring only **9 to 15 microseconds** for ML-KEM. The overhead represents the local QKD pool lookups and the `ROKDF` calculations used to integrate the QKD key into the final session key.
* **Bandwidth Overhead**: The hybrid mode introduces a static overhead of exactly **21 bytes** on the wire. This minor increase represents the serialization of the QKD key ID (`mock-qkd-key-id-12345`) sent from Alice to Bob to coordinate key retrieval.

### D. Quantifying the Starvation & Availability Knee
* **The Availability Knee**: The results show a clear bottleneck transition point. For example, on a **1 kbps** link, the system stays healthy at 10 handshakes per second. However, raising the rate to 20 handshakes per second instantly depletes the pool, resulting in a **0.0% occupancy** and forcing **16.5% of sessions to silently downgrade** to computational-only security.
* **Impact of QKD Key Generation Bounds**: If the system is deployed at realistic rates (e.g., 10 kbps or lower) without proper mitigation rules, high-throughput links will frequently deplete the key store. This demonstrates that without mechanisms like Admission Control (which rejects degraded sessions) or Per-Peer Quotas, the information-theoretic guarantee of hybrid HAKE is highly fragile under heavy load.

