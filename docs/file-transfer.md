# Policy-aware encrypted file transfer

Alice and Bob run in **separate processes**, exchange the existing four HAKE
messages over localhost TCP, and obtain QKD material from the mock KME over HTTP.
Files and receipts are protected by AES-256-GCM from `cryptography`.
This is a local experimental application of the testbed protocol, not a claim
of production cryptography or exact conformance to the cited HAKE paper.

## Run all five scenarios automatically

From the repository root, using the existing `.venv`:

```bash
make test
make transfer-verify
```

The verifier creates isolated Alice, Bob and KME processes on unused loopback
ports, runs the five cases, compares received files byte-for-byte, saves evidence
under `output/file-transfer/<UTC timestamp>-<run ID>/`, and stops only its own
service processes. It does not require a pre-existing KME or receiver.

Open `REPORT.md`, `results.json`, or `results.csv` in that run directory.
The `*-audit.jsonl` files and terminal logs record the actual operations.
`requirements-freeze.txt` records the installed dependencies. Native tests cover
ML-KEM-512, ML-KEM-768, ML-KEM-1024 and FrodoKEM-976-AES; the default demonstration
uses ML-KEM-768. For another algorithm:

```bash
.venv/bin/python -m qkd_hake.cli transfer verify-demo --algorithm FrodoKEM-976-AES
```

Expected outcomes:

| Situation | Outcome |
|---|---|
| Keys available | `DELIVERED`, `HYBRID_QKD` |
| Pool empty, fallback allowed | `DELIVERED`, `PQC_ONLY`, explicit reason |
| Pool empty, hybrid required | `QUEUED`; Bob publishes no file |
| Pool refills | New handshake; queued transfer becomes `DELIVERED`, `HYBRID_QKD` |
| Ciphertext changed | `FAILED`, `authentication_failed`; Bob publishes no file |

The functional verifier uses a reproducible generated CSV fixture (seed
20261006), one run per case and no warm-up. Cryptographic randomness is never
seeded. Its durations are functional-run observations, not performance benchmarks.

## Interactive demo: server plus two endpoint terminals

Provision pinned identities **once**:

```bash
make transfer-init
```

This creates Alice's identity with Bob's pinned public key and Bob's identity
with Alice's pinned public key. Private files have mode `0600`; the directory
has mode `0700`. Existing identity files are never overwritten. To create a
separate experiment, use `transfer init --directory PATH` and pass its identity
paths to the endpoints. The endpoints do not exchange or trust unverified public
keys received over the transfer connection.

Start the mock KME in a server terminal:

```bash
QKD_INITIAL_KEYS=8 QKD_POOL_DEPTH=8 QKD_REFILL_BPS=0 make server
```

In Bob's terminal:

```bash
make transfer-receive
```

In Alice's terminal, select a real file by its path:

```bash
.venv/bin/python -m qkd_hake.cli transfer send /absolute/path/to/file.pdf --policy hybrid-required
```

Both terminals show the session mode. Bob saves the verified file under
`transfer-demo/received/<transfer UUID>-<original filename>`.

Allow an explicitly labelled fallback for an ordinary file:

```bash
.venv/bin/python -m qkd_hake.cli transfer send /absolute/path/to/file.csv --policy allow-pqc
```

Files are opaque bytes: PDFs, images, datasets, empty files and binary data all
use the same transfer path. The demo intentionally caps each file at **16 MiB**
and authenticates it in memory before publishing it. Larger-file streaming and
partial-transfer resume are outside this version.

## Queue and automatic retry

With an empty KME (`QKD_INITIAL_KEYS=0`, `QKD_REFILL_BPS=0`), a strict transfer
remains queued. The queue is a durable SQLite database of references to source
files and their size/hash; it does not copy the plaintext or store session keys.

```bash
.venv/bin/python -m qkd_hake.cli transfer send /absolute/path/to/file.pdf --policy hybrid-required
.venv/bin/python -m qkd_hake.cli transfer queue
```

To demonstrate automatic recovery manually, start an empty pool with a slow
refill, then send before its first key becomes available:

```bash
# Server terminal: restart the mock KME with these settings.
QKD_INITIAL_KEYS=0 QKD_POOL_DEPTH=8 QKD_REFILL_BPS=32 make server

# Alice terminal: one key arrives every eight seconds.
.venv/bin/python -m qkd_hake.cli transfer send /absolute/path/to/file.pdf --policy hybrid-required --wait --interval 1 --max-wait 60
```

Or enqueue several files without sending, then drain the queue:

```bash
.venv/bin/python -m qkd_hake.cli transfer enqueue /absolute/path/to/a.pdf --policy hybrid-required
.venv/bin/python -m qkd_hake.cli transfer enqueue /absolute/path/to/b.csv --policy allow-pqc
.venv/bin/python -m qkd_hake.cli transfer work --wait --interval 1 --max-wait 60
```

The worker retries only resource-policy failures, creates a fresh HAKE session
for every attempt, and reuses one mitigation manager across its sessions. The
rate quota defaults to 10 requests/s. Separate worker invocations reset that
in-memory rate history; the persisted queue and source hashes remain intact.
The worker exits when the pending queue is drained or the deadline is reached.
A queued job stays queued after the deadline and can be resumed by another worker.
Only one worker may run per queue directory.

## Live status, tampering, and audit

```bash
.venv/bin/python -m qkd_hake.cli transfer status --watch --interval 1
.venv/bin/python -m qkd_hake.cli transfer status --watch --count 5
.venv/bin/python -m qkd_hake.cli transfer send /absolute/path/to/file.csv --policy hybrid-required --tamper
```

`status` displays available keys, capacity and occupancy. Each transfer attempt
also records a current status snapshot. `--tamper` is an explicit negative-test
switch: it flips one encrypted byte after encryption. The expected result is an
authenticated rejection, with no received file.

Audit paths default to `transfer-demo/alice-audit.jsonl` and
`transfer-demo/bob-audit.jsonl`. They record event, transfer ID, filename, size,
policy, visible mode, reason, duration, attempt count and nonsecret session
identifiers. They never record secret keys, QKD bytes or derived session keys.
The receiver records the file commit before sending its encrypted receipt.

Exit codes: `0` = delivered/drained; `1` = failed or delivery uncertain;
`2` = still queued. The intentional tamper test returns `1`. The first strict,
empty-pool attempt returns `2`; these are expected outcomes in the verifier.

## Verification and failure semantics

- The handshake binds roles, algorithm, nonces, public keys, ciphertexts, QKD ID
  and the selected runtime mode. The displayed `PQC_ONLY` name abbreviates
  `SECURITY_LEVEL_DEGRADED_PQC_ONLY`; the cryptographic transcript is unchanged.
- HKDF-SHA256 derives separate Alice-to-Bob and Bob-to-Alice AES-256-GCM keys
  from the confirmed HAKE key, salted by the complete transcript hash.
- Each direction uses a strictly increasing 96-bit counter nonce. Fresh
  handshakes give fresh keys. Record type, direction, sequence and transcript
  hash are authenticated; replay and substitution are rejected.
- The filename, size, transfer UUID, digest, policy and mode are sent in an
  encrypted authenticated offer. The receiver independently enforces strict
  policy. The authenticated receipt binds the delivered file, mode and digest.
- Bob decrypts/authenticates the complete file, verifies size and digest, then
  atomically publishes it without overwriting an existing destination.
  Unsafe paths and control characters in filenames are rejected.
- Authentication failures and later QKD retrieval failures **never** trigger a
  PQC fallback or an automatic retry. Missing/invalid QKD material is rejected.
- A source file modified while queued fails instead of silently transferring
  different contents. In-flight jobs interrupted by a crash become `UNKNOWN`
  when the next exclusive worker starts.
- A lost delivery receipt is `UNKNOWN`, not automatic retransmission: Bob may
  already have committed the file. Inspect Bob's audit/output before creating
  a replacement job. This avoids falsely reporting failure or duplicate delivery.

The mock KME's test identity header is not production access control. All demo
listeners bind to loopback. Provisioned identity files and the generated
`private-identities/` directory are private runtime artifacts; exclude them
from shared research reports.

Library reference: [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).
