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

A paired performance suite was run with **1,000 Hybrid/Pure-PQC pairs for each KEM**, giving 1,000 recorded Hybrid runs and 1,000 recorded Pure-PQC runs per KEM. Across the four evaluated KEMs, this produced **8,000 recorded handshake measurements** in total. The benchmark covers two main families of KEMs: Module Lattice-based KEMs (ML-KEM) and Unstructured Lattice-based KEMs (FrodoKEM).

### Benchmark Results Table (1,000 Paired Runs per KEM)

| Algorithm | Handshake Mode | Median Latency | 95th Percentile Latency | Message Size on Wire |
| :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | HYBRID | 2.032 ms | 3.831 ms | 3,268 bytes |
| | PURE_PQC | 2.045 ms | 3.891 ms | 3,232 bytes |
| **ML-KEM-768** | HYBRID | 2.651 ms | 4.311 ms | 4,612 bytes |
| | PURE_PQC | 2.655 ms | 4.329 ms | 4,576 bytes |
| **ML-KEM-1024** | HYBRID | 3.578 ms | 4.779 ms | 6,436 bytes |
| | PURE_PQC | 3.572 ms | 4.740 ms | 6,400 bytes |
| **FrodoKEM-976-AES** | HYBRID | 73.998 ms | 146.090 ms | 63,172 bytes |
| | PURE_PQC | 72.717 ms | 145.288 ms | 63,136 bytes |

The benchmark used paired Hybrid/Pure-PQC runs under the same benchmark conditions. The results show that the selected KEM has a substantially larger effect on software-level handshake latency than the difference between Hybrid and Pure-PQC modes. The median Hybrid latency overhead relative to Pure-PQC is approximately -0.64% for ML-KEM-512, -0.15% for ML-KEM-768, +0.17% for ML-KEM-1024 and +1.76% for FrodoKEM-976-AES. These small differences indicate that the measured addition of QKD material has a limited latency impact relative to the KEM computation in the tested configurations.

The serialized measurements show a consistent **36-byte difference** between the Hybrid and Pure-PQC configurations. This corresponds to the transmitted QKD key identifier used by the current testbed; the QKD secret itself is not transmitted during the handshake.

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
| | **100 req/s (Knee)** | **51.8%** | **0.0%** | **YES (Starved)** |
| **100 kbps** | 1 to 100 req/s | 100.0% | 99.2% | NO |

---

## 4. Analysis & Key Takeaways

### A. ML-KEM vs. FrodoKEM Latency

* **ML-KEM (Structured Lattices)** provides fast handshakes in the measured environment, with median latencies ranging from **2.032 ms to 3.578 ms** across the three ML-KEM variants.

* **FrodoKEM-976-AES (Unstructured Lattices)** has substantially higher measured latency, with a median of **73.998 ms in Hybrid mode** and **72.717 ms in Pure-PQC mode**. The corresponding p95 latencies are **146.090 ms** and **145.288 ms**, respectively.

### B. Bandwidth on the Wire

* **ML-KEM** keeps payloads relatively lightweight, with measured Hybrid message sizes ranging from **3,268 bytes to 6,436 bytes** across the three variants.

* **FrodoKEM** requires a much larger **63,172-byte Hybrid payload** in the measured configuration.

### C. Hybrid QKD-PQC Protocol Overhead

* **Computational Overhead**: The measured median latency difference between `HYBRID` and `PURE_PQC` is small across the evaluated KEMs. The median Hybrid overhead is approximately **-0.64% for ML-KEM-512, -0.15% for ML-KEM-768, +0.17% for ML-KEM-1024, and +1.76% for FrodoKEM-976-AES**. The negative values for ML-KEM-512 and ML-KEM-768 indicate that Hybrid was marginally faster in those particular measurements; these small differences should be interpreted as measurement variation rather than as a Hybrid performance advantage.

* **Bandwidth Overhead**: The Hybrid mode introduces a static **36-byte** difference relative to the corresponding Pure-PQC configuration. This difference is due to the transmitted QKD key identifier used to retrieve the shared QKD material. The QKD secret itself is not transmitted as part of the handshake.

### D. Quantifying the Starvation & Availability Knee

* **The Availability Knee**: The results show a clear bottleneck transition point. For example, on a **1 kbps** link, the system stays healthy at 10 handshakes per second. However, raising the rate to 20 handshakes per second results in **0.0% occupancy** and a measured **83.5% QKD success rate** in the supplied bottleneck table.

* **Impact of QKD Key Generation Bounds**: If the system is deployed at realistic rates (e.g., 10 kbps or lower) without proper mitigation rules, high-throughput links will frequently deplete the key store. This demonstrates why mechanisms such as Admission Control or Per-Peer Quotas are relevant when QKD-backed operation must be maintained under heavy load.
