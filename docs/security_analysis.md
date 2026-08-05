# Clermont-Henrich 2026 Hybrid HAKE Security Analysis

This document provides a security analysis of the signature-free Hybrid Authenticated Key Exchange (HAKE) protocol combining Post-Quantum Cryptography (PQC) and Quantum Key Distribution (QKD) based on the Clermont-Henrich 2026 paper.

---

## 1. Compromise Matrix

We evaluate the security of the derived session key ($k_{2h}$) under four compromise scenarios (failure modes) against three key security properties:
- **Key Secrecy**: The confidentiality of the session key against a passive/active eavesdropper.
- **Perfect Forward Secrecy (PFS)**: Compromise of long-term static identity keys does not compromise past session keys.
- **Information-Theoretic Security (ITS)**: The session key achieves security that cannot be broken even by an adversary with unbounded computational power.

| Failure Mode / Scenario | Key Secrecy | Perfect Forward Secrecy (PFS) | Information-Theoretic Security (ITS) | Rationale / Discussion |
| :--- | :--- | :--- | :--- | :--- |
| **1. Both Secure (PQC & QKD)** | **Secure** | **Yes** | **No** (Computational due to PQC KEM) | Baseline operating mode. Session key confidentiality is guaranteed by both independent layers. |
| **2. QKD Broken** (KEM Secure) | **Secure** | **Yes** | **No** (Computational security) | If the QKD channel is eavesdropped or the KMS is compromised, the protocol degrades gracefully to the computational security of the KEM layer. |
| **3. PQC Broken** (QKD Secure) | **Secure** | **Yes** (Inherited from QKD) | **Yes** (If QKD is ITS and no KEM keys are reused) | If the static/ephemeral KEMs are computationally broken, the secret QKD key component $k_{qkd}$ prevents session key compromise, providing a quantum safety net. |
| **4. Both Broken** (PQC & QKD) | **Compromised**| **No** | **No** | If the adversary has compromised the QKD key pool and can break the underlying PQC KEMs, no security guarantees remain. |

---

## 2. CK01 Model Game-Hop Proof Outline

We analyze the security of the Clermont-Henrich HAKE protocol in the Canetti-Krawczyk (CK01) adversarial model. 

### Oracles and Adversary Powers
An active adversary $\mathcal{A}$ controls all communications and can invoke the following queries:
1. **Send(session, message)**: Sends a message to a session and obtains the response.
2. **Session-State Reveal(session)**: Exposes the internal ephemeral state of a session (e.g., $k_1$, $k_2$, $k^*$).
3. **Corrupt(principal)**: Exposes the long-term static identity secret key ($sk_a$ or $sk_b$) of a principal.
4. **Session-Key Reveal(session)**: Exposes the final session key of a completed session.
5. **Test(session)**: The target query. The adversary is given either the real session key or a random key of the same length, and must guess which it is.

### Freshness Definition
A session is **fresh** if:
- Neither the session nor its matching partner has been queried with `Session-Key Reveal`.
- No `Corrupt` query has been made to either peer prior to the completion of the session (pre-compromise).

### Game Hops Outline

#### Game 0 (Original Game)
The environment executes the real HAKE protocol. The adversary's advantage is $|\Pr[S_0] - 1/2|$ where $S_0$ is the event that the adversary correctly guesses the Test query challenge.

#### Game 1 (Simulation of QKD / KMS)
We replace the ETSI GS QKD 014 mock KMS keys with truly random, independent keys unknown to the adversary. By the information-theoretic properties of QKD key generation, this hop is indistinguishable from Game 0.
$$\Pr[S_1] = \Pr[S_0]$$

#### Game 2 (Ephemeral KEM Security)
We replace the ephemeral KEM shared secret $k^*$ with a truly random string in the target session.
- **Transition**: IND-CCA security of the ephemeral KEM. Any adversary distinguishing this hop can be used to construct a solver for the underlying IND-CCA KEM challenge.
$$|\Pr[S_2] - \Pr[S_1]| \leq \text{Adv}_{\text{KEM}}^{\text{IND-CCA}}(\mathcal{A})$$

#### Game 3 (KDF Transition)
We replace the multi-input KDF $F$ (using SHA-3-512 in the Random Oracle Model) outputs with random values. Since $k^*$ (and/or $k_{qkd}$) is uniform and independent of the adversary's view:
- The input to the Random Oracle has high entropy.
- The output of the ROKDF is computationally indistinguishable from a random oracle output.
$$\Pr[S_3] = \Pr[S_2]$$

#### Game 4 (Confirmation Tags)
We replace the MAC tags ($\tau_1, \tau_2, \tau_3$) with random tags.
- **Transition**: IND-CPA/unforgeability of HMAC-SHA-256. If the keys are secure, tag forgery is negligible.
$$|\Pr[S_4] - \Pr[S_3]| \leq \text{Adv}_{\text{HMAC}}^{\text{UF-CMA}}(\mathcal{A})$$

At Game 4, the session key is perfectly independent of the transcript and all other oracle queries. Thus, the adversary has zero advantage.
$$\Pr[S_4] = 1/2$$
By compiling the bounds across all games, we establish the session key secrecy and authentication guarantees of the hybrid protocol.
