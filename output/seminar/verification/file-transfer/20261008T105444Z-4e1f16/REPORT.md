# File-transfer verification

Algorithm: ML-KEM-768; liboqs 0.16.0; cryptography 46.0.7.

Separate Alice, Bob and mock KME processes communicated over localhost TCP and HTTP.

| Scenario | Result | State | Mode | Attempts | File verified |
|---|---|---|---|---:|---|
| hybrid | PASS | DELIVERED | HYBRID_QKD | 1 | True |
| explicit-pqc-fallback | PASS | DELIVERED | PQC_ONLY | 1 | True |
| tampered-ciphertext | PASS | FAILED | HYBRID_QKD | 1 | False |
| hybrid-required-queued | PASS | QUEUED | none | 1 | False |
| refill-resumes-with-fresh-handshake | PASS | DELIVERED | HYBRID_QKD | 17 | True |

The queued case intentionally returns exit code 2; the tampered case intentionally returns 1.
No received file was published for either case before successful verification.
All successful files were compared byte-for-byte with the source. Each retry used a fresh HAKE nonce.
Fixture randomness is reproducible; cryptographic randomness is deliberately unseeded.
One functional run per scenario, no warm-up; durations are observations, not benchmark estimates.

Audit logs contain modes, policy reasons, sizes and durations, never key material.
Private provisioning files are under private-identities/ with mode 0600; do not include them in a report bundle.

See results.json for environment and raw results; scenario directories contain commands and both terminal logs.
