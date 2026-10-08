# Understanding and presenting the QKD–PQC HAKE testbed

Prepared from the repository and executed experiments on 8 October 2026.
Read this together with the [complete annotated source](../output/seminar/annotated-source.html)
and [new policy comparison](../output/seminar/policy-comparison/report.html).
The annotations retain the original line numbers and include every line of
application code, tests, benchmark/plot scripts, architecture scripts, and
build/configuration files. They explain Python syntax alongside the module's
purpose; this guide explains the reasoning connecting those lines.

## 1. What you should say in your opening minute

“This project studies a resource problem in hybrid authenticated key exchange.
Two applications combine post-quantum KEM secrets with a shared key supplied
by a mock QKD key-management service. Each hybrid session consumes one fresh
256-bit QKD key. The key supply is finite, so a fast cryptographic handshake
does not guarantee that every request can receive hybrid security. We measure
depletion and compare explicit PQC fallback, request quotas, and admission
control. We also demonstrate policy-aware encrypted file transfer.”

The research contribution is the **resource experiment and policy tradeoff**.
The project does not implement quantum optics, invent ML-KEM, or establish a
new security proof. It is an experimental software testbed.

Three separate questions organize the entire project:

1. Can Alice and Bob obtain matching, transcript-bound keys?
2. How many sessions can receive fresh QKD material at a given supply rate?
3. What happens to availability, security mode, resource use, and local
   decision cost when that material becomes scarce?

## 2. Concepts, from the beginning

### Bits, bytes, identifiers, and encodings

A bit is 0 or 1. Eight bits make one byte. A 256-bit key occupies 32 bytes.
Python `bytes` holds binary values; `str` holds text. Cryptographic APIs work
on bytes. HTTP JSON cannot directly contain arbitrary bytes, so the API uses
Base64, a reversible encoding. A 32-byte value becomes 44 Base64 characters,
including padding. **Base64 does not encrypt anything.**

A QKD key ID is a lookup reference, not the key itself. Here it is a UUID
string, normally 36 ASCII bytes. Alice can send Bob the ID so Bob can ask
the KME for the matching secret. Never show the actual key bytes in slides,
logs, or a terminal demo.

### Encryption, authentication, and key exchange

Encryption hides content. Authentication establishes who possesses the
required secret or whether a message was altered. Key exchange establishes
shared secret material. These are related but distinct operations.

An unauthenticated exchange could establish a secret with an attacker
pretending to be the intended peer. Therefore both peers need a trustworthy
association between identity and long-term public key. The file-transfer
demo provisions and pins that association in advance.

### What a KEM does

A Key Encapsulation Mechanism has three operations:

```text
(public_key, secret_key) = KeyGen()
(ciphertext, shared_secret_sender) = Encaps(public_key)
shared_secret_receiver = Decaps(secret_key, ciphertext)
```

The two shared secrets should agree. The ciphertext can travel over the
network; the secret key and shared secret must not. Encapsulation is not
the application-file encryption step: the application later derives an
AES key from the handshake's output.

Anyone can encapsulate to a public key. Encapsulation alone therefore does
not prove the sender's identity. In this handshake, possession of the
corresponding long-term private keys is demonstrated through MACs keyed
by encapsulated secrets. That reasoning depends on authentic public-key
provisioning and the protocol's assumptions.

ML-KEM is standardized in NIST FIPS 203 and is based on module lattices.
Its three parameter sets are ML-KEM-512, ML-KEM-768, and ML-KEM-1024;
the suffix is not the session-key length. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

FrodoKEM uses learning with errors without ML-KEM's module structure. The
tested FrodoKEM-976-AES parameter set has much larger public keys and
ciphertexts. Its shared secret is 24 bytes, while ML-KEM's is 32 bytes.
The final session key in this code is 32 bytes for every algorithm because
the KDF produces that output length. Expanding a key does not create extra
input entropy. [OQS FrodoKEM parameters](https://openquantumsafe.org/liboqs/algorithms/kem/frodokem.html).

The Python wrapper in `crypto/kem.py` delegates actual KEM mathematics to
liboqs. You are not expected to claim that Python code implements lattice
arithmetic: it selects an algorithm and calls the native implementation.

### QKD, the KME, and the SAE

QKD means Quantum Key Distribution. A real system uses quantum communication
plus authenticated classical processing to establish shared key material.
This repository simulates the delivery and finite supply of that material.
It generates software random bytes with `secrets.token_bytes`; it does not
send photons, perform sifting, estimate quantum bit errors, or run privacy
amplification.

KME means Key Management Entity: the service managing keys. SAE means Secure
Application Entity: an application requesting them. Alice and Bob are SAEs.
The mock collapses the delivery model into one in-memory server accessible
to both applications.

ETSI GS QKD 014 defines a REST key-delivery interface, including status,
new-key requests and retrieval by key ID. The standard requires HTTPS and
mutual authentication. This repository's HTTP and `X-SAE-ID` header are a
local mock, not equivalent access control.
[ETSI GS QKD 014, clauses 4–6](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_QKD014v010101p.pdf).

### Hashes, MACs, KDFs, and transcripts

A hash maps arbitrary bytes to a fixed-size digest. A digest alone does not
authenticate its source. A MAC uses a secret key, so a valid tag provides
evidence of possession of that key and protects the tagged message.

HMAC is a standard MAC construction. Here handshake tags use HMAC-SHA-256.
`hmac.compare_digest` avoids a naive early-exit byte comparison for tag
verification. It does not make all Python operations constant-time.

A KDF derives keys from secret inputs and context. Domain-separation labels
identify different purposes so that a session key is not accidentally used
as a confirmation key. HKDF separates extraction and expansion. The active
handshake instead uses a function called `rokdf`, implemented as SHA3-512
over a label and length-prefixed fields.

A transcript is the agreed record of a handshake. Here it binds version,
ordered identities, algorithm, both nonces, long-term public keys, ephemeral
public key, ciphertexts, QKD key ID, and security mode. If the two parties
build different transcripts, their derived keys or confirmation tags differ.

Length-prefixing avoids ambiguity: concatenating `ab` with `c` produces
the same bytes as `a` with `bc`. Encoding each field's length before its
contents distinguishes those cases. `serialize_fields` uses a four-byte
big-endian length for each field.

### Long-term versus ephemeral keys

Long-term identity keys persist across sessions. Bob also generates an
ephemeral KEM key pair for each handshake. Alice encapsulates a fresh secret
to it. This is intended to support forward secrecy: later theft of static
identity keys should not by itself reveal previous sessions.

That is a design objective subject to assumptions, not a property established
by a round-trip test. Python objects retain secrets while referenced; this
code does not guarantee secure erasure. A complete proof must address
ephemeral-state compromise, identity compromise, QKD access, and freshness.

### Computational versus information-theoretic security

Computational security relies on bounds on an attacker's computation and
cryptographic hardness assumptions. Information-theoretic security is a
stronger statement about the information available even to an unbounded
attacker, under a specified model.

Do not call this mock or its AES-GCM file transfer “unconditionally secure.”
Adding software random bytes and SHA3 does not establish that theorem.
The reference paper describes a conditional information-theoretic guarantee
under its own assumptions; that guarantee cannot simply be imported into
this implementation. [Clermont and Henrich, ePrint 2026/1231](https://eprint.iacr.org/2026/1231).

## 3. Follow the execution paths

```text
Makefile / qkd-hake command
          |
          +-- demo ------ in-memory pool + prototype HKDF combiner
          |
          +-- server ---- FastAPI routes -> QKDKeyPool
          |
          +-- benchmark - AliceSession/BobSession -> liboqs + active ROKDF
          |               QKD callback is an in-memory fixed fixture
          |
          +-- sweep ----- simulated clock -> QKDKeyPool -> depletion CSV
          |
          +-- policy-sweep - same seeded arrivals for each policy
          |                 actual pool + mitigation checks -> event CSV
          |
          +-- transfer -- TCP handshake + HTTP KME access
                          -> directional AES-GCM channel
                          -> verified file publication + receipt
                          -> SQLite queue + audit log
```

This separation matters. A 0.15 ms in-process handshake measurement and a
60 ms file transfer are measuring different work. The latter includes
transport, HTTP calls, file operations, and application processing.

## 4. The key pool, step by step

`qkd_mock/pool.py` owns the model. Its important variables are:

| Variable | Meaning |
|---|---|
| `refill_bps` | Modeled generation rate, in bits/second |
| `depth` | Maximum available-key count |
| `_available` | Keys that Alice can still request |
| `_fractional_bits` | Generation credit insufficient for complete keys, with overflow handling |
| `_last_refill` | Previous lazy-refill timestamp |
| `_issued` | Keys already delivered to the requesting SAE, awaiting peer retrieval |
| `_outstanding` | Number of those pending keys per directed peer pair |
| `_lock` | Serializes in-process pool state changes |

The pool is **lazy**: no background thread continuously adds keys. A status
or issue operation computes the elapsed time, multiplies it by `refill_bps`,
converts complete 256-bit portions into keys, and caps the result at depth.
An injected clock permits deterministic experiments without real waiting.

`issue('alice', 'bob', 1)` checks quota and availability, creates random
bytes and an ID, stores them under `(alice, bob, ID)`, decrements availability,
increments outstanding count, and returns the key to Alice.

`retrieve('alice', 'bob', [ID])` removes the stored entry and decrements
outstanding count. It returns the same bytes to Bob. It does **not** return
a key to `_available`: the session has consumed that key. A subsequent
retrieval of the same ID fails.

There are two different meanings of quota in this repository:

* Pool quota: limits keys issued but not yet retrieved, per directed pair.
* Mitigation quota: limits admitted QKD request checks per peer in a rolling
  one-second window. A shared manager is needed across multiple sessions.

The original depletion sweep only issues keys and does not retrieve them;
its pending-key dictionary therefore grows during a run. The new policy
comparison immediately retrieves each successful key to model a completed
request and avoid that accumulation.

The current pool also has a duplicate-ID edge case: requesting the same ID
twice in one retrieval passes the initial existence check, then the second
`pop` fails after the first has modified the dictionary. This was confirmed
with an isolated in-memory probe. It is a known limitation, not a fix made
as part of this explanatory/policy-comparison work.

## 5. The REST API

`models.py` describes input/output JSON using Pydantic. For example,
`number` must be between 1 and 128. FastAPI validates request bodies and
serializes responses. `server.py` creates one pool and attaches it to
`app.state.pool`. Its route functions adapt HTTP to pool operations.

| Operation | Route | Effect |
|---|---|---|
| Health | `GET /health` | Reports process readiness; no key is consumed |
| Status | `GET /api/v1/keys/bob/status` | Returns pool count/capacity for Alice's request |
| Issue | `POST /api/v1/keys/bob/enc_keys` | Alice requests a new key for Bob |
| Retrieve | `POST /api/v1/keys/alice/dec_keys` | Bob requests Alice's key by ID |

GET variants also exist for single-key issuance/retrieval. Missing caller
identity produces 401. Unsupported size produces 400. Exhaustion and pool
quota produce 503. Unknown/reused IDs normally produce 400. Schema validation
can produce 422 before a route runs.

`client.py` constructs URLs and the test identity header, makes HTTP requests,
calls `raise_for_status`, and decodes Base64. It requests 256-bit keys even
though the pool can be configured for other byte-aligned sizes. The active
handshake also requires exactly 32 QKD bytes.

## 6. The actual four-message handshake

Read `protocol/hake.py` in this order: `AliceSession.__init__`, `message1`,
`BobSession.__init__`, `message2`, Alice's `message3`, Bob's `message4`,
then Alice's `derive_and_verify`. The file groups methods by role, whereas
execution alternates roles.

Before starting, Alice knows Bob's authenticated static public key and Bob
knows Alice's. In the file demo, `transfer/identity.py` provisions this
relationship out of band.

Notation: `||` means concatenation; `S(...)` means `serialize_fields`;
`pk` is public key, `sk` is private key, `ct` is KEM ciphertext, `k` is a
shared secret, and `tau` is a MAC tag. All following equations describe
the inspected implementation, not a claim of paper-exact correspondence.

### Message 1: Alice to Bob

```text
(ct1, k1) = Encaps(pk_B)
Alice -> Bob: (ct1, nonce_A)
```

Alice creates a fresh 16-byte nonce when her session is constructed.
`message1()` encapsulates to Bob's static key and saves `ct1` and `k1`.
Only the ciphertext and nonce are sent. The nonce is public freshness
context, not an encryption key.

### Message 2: Bob to Alice

```text
(pk_E, sk_E) = KeyGen()
k1 = Decaps(sk_B, ct1)
(ct2, k2) = Encaps(pk_A)
s = ct1 || ct2
tau1 = HMAC-SHA256(k1, pk_E || nonce_B || s || "A")
Bob -> Alice: (pk_E, tau1, ct2, nonce_B)
```

The ephemeral public key is protected by a tag under `k1`. Alice already
knows `k1`, and Bob needed his static private key to recover it. The literal
`b'A'` is a domain/role-related label in the implementation; preserve it
when explaining the code rather than “correcting” it based on its name.

### Message 3: Alice to Bob

Alice reconstructs and verifies `tau1` **before** requesting QKD material.
On failure she raises `HandshakeError`; this is not a reason to downgrade.

```text
k2 = Decaps(sk_A, ct2)
(ct_star, k_star) = Encaps(pk_E)
(qkd_key, qkd_id) = acquire_QKD_if_policy_allows()
tau2 = HMAC-SHA256(k2, UTF8(qkd_id) || ct_star || s || "B")
Alice -> Bob: (ct_star, qkd_id, tau2)
```

The active Alice implementation checks request quota, then pool status and
the 5% admission threshold, then fetches a key. By default these checks are
combined. The policy experiment deliberately isolates them in separate arms
to measure their individual effects.

If resource acquisition is unavailable and fallback is allowed, Alice chooses
`SECURITY_LEVEL_DEGRADED_PQC_ONLY`. If fallback is forbidden, she raises
`QKDUnavailableError`. If a callback claims to deliver a key but returns
`None`, an empty key, a wrong-length key, or an empty ID, validation rejects
it even when fallback is enabled. Malformed delivery is not successful QKD.

### Message 4: Bob to Alice

Bob verifies `tau2` using his `k2`, decapsulates `ct_star` with `sk_E`, and
retrieves the QKD key by ID. A nonempty ID with failed/invalid retrieval
aborts; Bob does not silently fall back. An empty ID explicitly corresponds
to the degraded mode in this flow.

Both sides construct:

```text
T = S(version, id_A, id_B, algorithm, nonce_A, nonce_B,
      pk_A, pk_B, pk_E, ct1, ct2, ct_star, qkd_id, security_mode)
h = SHA3-256(T)
c_kem = S(id_A, pk_A, id_B, pk_B, pk_E, k1, k2, k_star, h)
c_qkd = S(id_A, id_B, qkd_id, h)

KH = SHA3-512(UTF8("KEM-QKD-Hybrid KEX") ||
              S(k_star, c_kem, sigma_qkd, c_qkd))
k1h = KH[0:32]       # confirmation key
k2h = KH[32:64]      # session key

tau3 = HMAC-SHA256(k1h, S(k1, qkd_id, pk_E, tau1, k2, tau2, h))
Bob -> Alice: tau3
```

In hybrid mode `sigma_qkd` is the delivered key. In the explicit degraded
mode it is an empty field, accompanied by a different transcript-bound mode.
This is not permission to treat failed hybrid delivery as an empty secret:
the mode decision and validation occur first.

Alice derives the same values and checks `tau3`. She returns a
`HandshakeResult(session_key, security_mode, transcript)` only after success.
The returned transcript is `T || tau3`. `tau1` and `tau2` participate in the
confirmation calculation but are not separate fields in `T` itself.

Bob does not receive a final handshake MAC under `k1h` from Alice. In the
file-transfer layer, her first authenticated encrypted offer supplies
evidence that she has derived the channel key. Do not call the four-message
API symmetric final-key confirmation without explaining this distinction.

The mode string is reconstructed and bound to the transcript; it is not
an independent `security_mode` field in message 3. The application maps
the long degraded string to the display label `PQC_ONLY`.

### Why there are three KEM secrets

`k1` supports evidence of Bob's static-key possession. `k2` supports evidence
of Alice's static-key possession. `k_star` comes from Bob's ephemeral key.
The final derivation includes all three and the QKD component. A public-key
substitution attack must be excluded by the provisioning/trust model; MACs
do not create that trusted mapping from nothing.

### The second KDF path is a prototype

`protocol/combiner.py` is separate from the active handshake. It chains
labelled HKDF-SHA3-256 extraction over static KEM, ephemeral KEM, and QKD
inputs and expands three keys: session, client confirmation, server
confirmation. It uses the `SecurityMode` enum.

`make demo` measures this prototype, not the ROKDF flow above. Also, the
prototype checks `qkd_key is None` but does not reject `qkd_key=b''`; an
isolated probe confirms that empty bytes are labeled hybrid there. The
active HAKE path has stronger QKD validation. Do not generalize its tests
into a claim that every helper enforces the same invariant.

## 7. File transfer: how the established key becomes useful

`transfer/handshake.py` transports the four messages as JSON over TCP.
Binary fields are Base64 encoded. A four-byte length prefix frames each
JSON message because TCP is a byte stream, not a message queue.
`wire._read` loops until enough bytes arrive and rejects early closure.
Frame-size checks run before reading the body.

`SecureChannel` hashes the completed transcript and uses HKDF-SHA256 to
derive two directional 256-bit AES-GCM keys from the session key. Alice's
send key is Bob's receive key, and vice versa. Each direction has its own
sequence counter starting at zero. The 12-byte representation of that
counter is the GCM nonce. Reusing a nonce with the same GCM key is unsafe;
fresh sessions and directional separation are therefore essential.

The authenticated additional data contains protocol version, direction,
sequence, record type, and transcript hash. AAD is authenticated context;
it is not the encrypted file content. A changed type, out-of-order sequence,
wrong transcript, wrong key, or modified ciphertext must fail.
[cryptography AESGCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/).

The record exchange is:

```text
Alice -> Bob: encrypted offer (name, size, digest, ID, policy, mode)
Alice -> Bob: encrypted file bytes
Bob   -> Alice: encrypted receipt (delivery status, matching metadata)
```

Bob validates the filename and policy, authenticates the file, checks its
length and SHA-256 digest, writes a temporary file, flushes it, and publishes
it with a hard link that refuses overwrites. The temporary file is removed
in a `finally` block. The authenticated digest catches inconsistent offered
metadata; an unauthenticated hash by itself would not replace AEAD.

The implementation reads a whole file into memory and limits files to
16 MiB. It is not a streaming large-file protocol. The 24 MiB outer frame
limit accommodates Base64 expansion and JSON overhead.

### Queue semantics

SQLite stores file paths, digests, policy, state, attempts, and timing;
it does not store session keys or copies of file plaintext. A source-file
change after enqueueing is detected before sending.

```text
QUEUED -> SENDING -> DELIVERED
                  -> QUEUED    resource unavailable; fresh retry allowed
                  -> FAILED    definitive error
                  -> UNKNOWN   file may have arrived; receipt uncertain
```

`hybrid-required` keeps a resource-starved job queued. `allow-pqc` permits
an explicitly recorded downgrade. Authentication failures never trigger
fallback or an automatic retry. Each queued retry starts a fresh handshake.

If Bob saves a file but the receipt is lost, Alice cannot conclude delivery
failed. `UNKNOWN` prevents automatic duplicate retransmission. A new
exclusive worker also changes interrupted `SENDING` records to `UNKNOWN`.
`fcntl.flock` makes this implementation Unix-oriented.

`Audit` permits only selected metadata field names. It writes mode, reason,
state, sizes, and timings, never intentionally the cryptographic secrets.
The allowlist is a defensive interface, not a proof that arbitrary values
could never be misused by future callers.

`identity.py` creates the provisioning directory with mode 0700 and files
with 0600, refuses existing identities, and suppresses dataclass repr.
The older `crypto/store.py` also stores long-term private keys in JSON but
does not implement these same protections. It is not the transfer demo's
provisioning path. Do not bundle either kind of private identity file.

## 8. Run it reliably

Use the repository root. A virtual environment isolates Python packages.
`-m package.module` runs a module using the selected interpreter.
`pip install -e` links the environment to your working source tree.

```bash
cd /Users/adityalanka/Downloads/qkd-hake-testbed
make setup
.venv/bin/pip install -e '.[dev,pqc,plots]'
make test
make demo
```

`make setup` installs the `dev` extra but not `pqc` or plotting dependencies.
The full tests and handshake need liboqs-python and native liboqs. Installation
may require native build tools; follow the wrapper's platform instructions
and finish it before seminar day. The local environment already passed the
four KEM tests. [liboqs-python installation](https://github.com/open-quantum-safe/liboqs-python).

Check algorithm availability without generating or printing keys:

```bash
.venv/bin/python - <<'PY'
import oqs
from qkd_hake.crypto.kem import SUPPORTED_ALGORITHMS
enabled = set(oqs.get_enabled_kem_mechanisms())
print('liboqs:', oqs.oqs_version())
for name in SUPPORTED_ALGORITHMS:
    print(name, name in enabled)
PY
```

### Safest complete application demonstration

```bash
make transfer-verify
```

This starts separate Alice, Bob, and KME processes on selected loopback
ports and exercises five cases: hybrid delivery, explicit fallback,
tamper rejection, strict queuing, and fresh-handshake delivery after refill.
It records commands, terminal logs, CSV, JSON, received files and a report
in a new `output/file-transfer/` run directory. It uses real wall-clock
refill in the queued case, which normally takes several seconds.

### Separate terminal demonstration

Provision once:

```bash
make transfer-init
```

Terminal 1:

```bash
make server
```

Terminal 2:

```bash
make transfer-receive
```

Terminal 3:

```bash
.venv/bin/python -m qkd_hake.cli transfer status
.venv/bin/python -m qkd_hake.cli transfer send README.md --policy hybrid-required
.venv/bin/python -m qkd_hake.cli transfer queue
```

The KME defaults to port 8000 and Bob to 9000, both on loopback. To inspect
status without exposing keys:

```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/v1/keys/bob/status -H 'X-SAE-ID: alice'
```

For starvation, stop the existing KME with Ctrl-C, then launch an empty,
non-refilling pool in Terminal 1:

```bash
QKD_INITIAL_KEYS=0 QKD_REFILL_BPS=0 make server
```

In Terminal 3:

```bash
.venv/bin/python -m qkd_hake.cli transfer send README.md --policy hybrid-required
.venv/bin/python -m qkd_hake.cli transfer send README.md --policy allow-pqc
```

The first command intentionally returns exit code 2 with `QUEUED`. The
second should report `PQC_ONLY` and delivery, with exit code 0. Exit code 1
means failure or unknown delivery. A queued result is not a cryptographic
failure and not a delivery success.

To resume, restart the KME with usable keys and run:

```bash
.venv/bin/python -m qkd_hake.cli transfer work --wait --interval 1 --max-wait 30
```

For a tamper demonstration, use a nonempty KME:

```bash
.venv/bin/python -m qkd_hake.cli transfer send README.md --tamper
```

It intentionally fails; Bob should not publish the modified file. Old failed
jobs remain visible in the persistent queue. Use a separate `--queue-dir`
for a clean presentation session if needed.

### Benchmarks and plotting

```bash
.venv/bin/python -m qkd_hake.cli benchmark --runs 1000 --warmup-runs 100
.venv/bin/python -m qkd_hake.cli sweep --measurement-seconds 60 --repeats 5 --pool-depths 16 64 128
.venv/bin/python -m qkd_hake.benchmarks.plot_performance_figures
.venv/bin/python -m qkd_hake.benchmarks.plot_wp6
```

Those original commands write fixed filenames under `results/` in the
current directory. They can overwrite previous results. The fresh evidence
for this guide was run from `output/seminar/verification/` to preserve the
existing historical CSVs.

The new comparison requires a new output directory:

```bash
.venv/bin/python -m qkd_hake.cli policy-sweep \
  --output results/policy-seminar-run-1 \
  --measurement-seconds 60 --warmup-seconds 10 --repeats 3 \
  --pool-depths 128 --rates 1 5 10 20 50 100 \
  --supplies-kbps 1 10 100 --quota 10 --seed 20261008
.venv/bin/python -m qkd_hake.benchmarks.policy_report results/policy-seminar-run-1
```

### Docker caveats

The Dockerfile installs native build tools and the PQC extra. Its default
command and Compose service run the small smoke demo. They do not start a
multi-service Alice/Bob/KME environment. The image also does not include
the plotting extra by default.

```bash
docker compose build
docker compose run --rm qkd-hake python -m pytest -q
docker compose run --rm qkd-hake python -m qkd_hake.cli transfer verify-demo
```

These Docker commands were inspected, not executed for this guide. Without
a bind mount, `--rm` removes the container and its generated results. Use
the verified local workflow for the seminar unless you rehearse Docker
separately. Dependencies and the liboqs Git reference are not fully pinned
by the Dockerfile, so “containerized” does not mean bit-for-bit reproducible.

## 9. The depletion mathematics you must understand

Let `R` be QKD supply in bits/second, `L` the key size in bits, `lambda`
the offered requests/second, and `D` the initial available keys.

```text
mu = R / L                          sustainable key supply, keys/second
net_drain = lambda - mu             when lambda > mu
T_deplete ≈ D / (lambda - mu)        continuous approximation
long_run_hybrid_fraction ≈ min(1, mu / lambda)
```

For this project's 256-bit keys:

| Supply | Sustainable modeled hybrid requests/s |
|---|---:|
| 1 kbps | 3.90625 |
| 10 kbps | 39.0625 |
| 100 kbps | 390.625 |

At 10 kbps and 100 requests/s, a full 128-key pool lasts approximately
`128 / (100 - 39.0625) = 2.1005 seconds`. The discrete sweep observed first
failure at 2.11 simulated seconds. Finite keys, discrete request arrivals,
and refill rounding explain small differences from the continuous equation.

At 10 kbps and 50 requests/s, depletion takes about 11.70 seconds. A ten-second
experiment can therefore show no starvation even though 50/s is not
sustainable. After depletion, the long-run hybrid fraction is about 78.125%.
This explains why the old ten-second table must not be presented as a
steady-state capacity result.

A larger pool delays failure during bursts. It does not change `R/L`.
Faster KEM code also does not change `R/L`. Actual end-to-end throughput
may additionally be limited by CPU, network, KME service time, or concurrency.

The corrected original sweep uses two phases: begin full and measure first
failure when overloaded; then measure requests after depletion. Underloaded
cases instead use ten simulated seconds of warmup. All arrivals are periodic.
The repeats have the same deterministic schedule, so repeated occupancy
results are not independent noisy physical-link trials.

## 10. What the policy comparison now measures

The added `benchmarks/policies.py` uses the actual pool and mitigation checks
with an injected virtual clock. It separates policies to make their effects
interpretable. It does not modify the cryptographic handshake message flow.

| Arm | Decision | On unavailable QKD |
|---|---|---|
| `reject_on_empty` | Control: attempt a key without extra guard | Reject |
| `explicit_downgrade` | Attempt a key without extra guard | Explicit `PQC_ONLY` |
| `per_peer_quota` | At most 10 admitted checks per peer per rolling second | Reject on quota or empty pool |
| `admission_control` | Require pre-request occupancy at least 5% | Reject below threshold or on empty pool |

Why the control? Otherwise rejecting on empty could be mistakenly attributed
to admission control. Why separate guards? The ordinary Alice flow combines
quota and admission; this comparison isolates one guard at a time.

The default experiment uses three supplies, six aggregate request rates,
one pool depth, two peer workloads, three repeats, and four policies:
`3 × 6 × 1 × 2 × 3 × 4 = 432 cases`.

Every case begins with an empty pool, runs ten simulated seconds of warmup,
then measures sixty seconds. Warmup state is retained; warmup requests are
excluded from the CSV and timing statistics. Starting empty prevents a full
initial reservoir from masquerading as supply capacity. It does not prove
that every policy has reached a stationary distribution; starting and final
occupancy are recorded.

Aggregate arrivals are periodic. A seeded generator assigns each request
to one of four peers. Balanced demand has equal expected shares; skewed
demand has expected shares 70%, 10%, 10%, 10%. Each policy sees the exact
same timestamps and peers for a paired configuration/repeat. Only this
workload randomness is seeded; cryptographic/random key bytes are not.

Successful acquisition consumes one key and immediately retrieves it for
Bob. This models no partner delay and disables the distinct outstanding-key
quota. Strict arms reject, rather than queue; queue delay is not measured.

### Costs and outputs

`policy_events.csv` contains every measured request: policy, workload,
simulated timestamp, peer, mode, reason, occupancy, actual guard CPU/wall
time, and actual complete-decision CPU/wall time. No keys or key IDs are
written. There are 803,520 measured events in the recorded default run.

`policy_summary.csv` contains each repeat's hybrid/PQC/reject counts, rates,
occupancy, consumption, reasons, and timing median/p95. `policy_peers.csv`
separates service by peer. `metadata.json` contains configuration, host,
Python/package versions, seed, source hashes, definitions, and assumptions.

The guard timer measures local policy evaluation, including its timer
overhead. Admission's guard includes a pool-status call. The complete-decision
timer additionally includes key issue/retrieval and random key/UUID generation
on hybrid success. CSV writing and post-decision occupancy observation are
outside both timed portions. These values are **not** network handshake
latencies; outcome mixtures must be considered when comparing timing.

The HTML report pools raw guard observations across repeats before computing
median/p95. It does not average percentiles and call the result a pooled p95.
Outcome percentages aggregate counts. The report plots the highest tested
rate and depth, and tabulates every configuration.

### Recorded example you can present

Settings: 10 kbps, 100 requests/s, depth 128, skewed peers, quota 10/s/peer,
three sixty-second measured windows following ten seconds of warmup.

| Policy | Hybrid | PQC-only | Rejected | Mean available keys |
|---|---:|---:|---:|---:|
| Reject-on-empty control | 39.07% | 0% | 60.93% | 0.00 |
| Explicit fallback | 39.07% | 60.93% | 0% | 0.00 |
| Per-peer quota | 33.76% | 0% | 66.24% | 119.72 |
| Admission threshold | 39.07% | 0% | 60.93% | 6.00 |

Interpretation: explicit fallback preserves modeled completion by reducing
the security mode of some sessions. Admission preserves the hybrid-only
requirement for successful sessions while rejecting excess demand. The
fixed quota throttles the heavy peer even when keys are available, reducing
utilization. At 100 kbps the same quota still limits hybrid service to 33.76%,
whereas the other arms provide 100% hybrid service in the model.

The 5% guard is a **pre-request check**. At depth 128, seven available keys
pass (5.47%); consuming one leaves six (4.69%). Therefore the measured six-key
reserve is expected. It is not a hard post-request 5% minimum, and the
ordinary REST status/get sequence is not atomic under concurrency.

In the 10 kbps skewed example, pooled median guard wall times were approximately
0.542 µs for control/fallback, 1.125 µs for quota, and 1.167 µs for admission.
These small, host-specific timings include instrumentation and are not
evidence of a statistically significant end-to-end performance difference.

Fairness is explicitly defined as Jain's index over each peer's hybrid
success fraction, `hybrid_requests / offered_requests`. Equal fractions give
1; all-zero service is undefined. Equal absolute quotas under unequal demand
can lower this metric. The quota arm's mean index here is about 0.834 versus
0.999 for the control. Do not say “quota improves fairness” without stating
which fairness objective you mean.

This comparison now supports resource and local-decision cost claims. It
still does not compare network handshake latency under concurrent policy
load, waiting-time distributions, adversarial identity creation, physical
QKD fluctuations, or the cost of enforcing authenticated identities.

## 11. Understand the original performance benchmark

`suite.run_performance_benchmarks` creates static key pairs outside the timed
handshake, executes warmups, and then alternates HYBRID/PURE_PQC order for
paired runs. Both modes use the same functions and algorithm but fresh
session randomness. The QKD callback returns a fixed test key and UUID.
It never contacts the REST server and does not model replenishment.

The timed section includes constructing sessions, the ephemeral key pair,
encapsulations, decapsulations, transcript derivation, MACs, and agreement
checking. `perf_counter_ns` measures elapsed time; `process_time_ns` measures
CPU consumed by the process. Dividing by one million converts ns to ms.

Median is the middle of the sorted observations. p95 is the estimated
95th-percentile latency, not “95% confidence.” The full benchmark uses linear
interpolation between sorted observations. The smoke helper uses a simpler
index rule, so their percentile methods differ.

Fresh run, 1,000 pairs per algorithm and 100 warmups per mode/algorithm:

| Algorithm | Hybrid median / p95 ms | PQC median / p95 ms | Hybrid raw field bytes |
|---|---:|---:|---:|
| ML-KEM-512 | 0.118 / 0.135 | 0.117 / 0.135 | 3,268 |
| ML-KEM-768 | 0.155 / 0.187 | 0.154 / 0.189 | 4,612 |
| ML-KEM-1024 | 0.203 / 0.225 | 0.202 / 0.224 | 6,436 |
| FrodoKEM-976-AES | 4.863 / 5.176 | 4.864 / 5.178 | 63,172 |

These are measurements from the pre-policy-change source snapshot recorded
in `output/seminar/verification/verification.json`; that snapshot's hashes
are retained. Host: macOS arm64, Python 3.11.13, liboqs 0.16.0. They differ
from older repository tables and must not be mixed into one dataset.

`bytes_on_wire` is actually a **sum of selected raw handshake field lengths**:
three KEM ciphertexts, one ephemeral public key, two 16-byte nonces, three
32-byte MACs, and the QKD ID. It excludes Base64, JSON, TCP/IP headers, KME
HTTP traffic, and pre-provisioned static public keys. Hybrid adds 36 raw
bytes for the UUID. This is not a packet-capture measurement.

The smoke benchmark uses constant fixture secrets and measures only the
prototype combiner. Its nanosecond result must not be labeled full HAKE
latency. The file-transfer verification uses one run per scenario and is
functional evidence, not a statistically meaningful performance benchmark.

## 12. Test it and know what a pass proves

```bash
make test
.venv/bin/pytest -v
.venv/bin/pytest tests/test_pool.py tests/test_api.py -v
.venv/bin/pytest tests/test_hake.py -v
.venv/bin/pytest tests/test_transfer.py -v
.venv/bin/pytest tests/test_policies.py -v
```

Pytest discovers `test_*.py` functions. `assert` expresses an expected result.
`pytest.raises` expects a specific error. `parametrize` runs one function
with multiple inputs; that is why the count of functions differs from
the number of executed cases. A fixture provides reusable setup/cleanup.
`tmp_path` gives each test isolated storage. `monkeypatch` replaces a behavior
temporarily to simulate faults such as a lost receipt.

| Test module | Evidence it provides |
|---|---|
| `test_pool.py` | Matching delivery, explicit exhaustion, single-use retrieval |
| `test_api.py` | REST key retrieval and 503 on empty pool |
| `test_combiner.py` | Prototype modes and different hybrid/fallback outputs |
| `test_kem.py` | Actual round trips for all four supported native KEMs |
| `test_hake.py` | Matching session keys, fallback, admission/quota paths, MAC tampering, invalid QKD delivery |
| `test_transfer.py` | Real loopback TCP/HTTP transfer, modes, refill/restart, AEAD modification/replay, path/size checks, lost receipts, audit restrictions |
| `test_policies.py` | Exact quota-window boundary, paired schedules, key conservation, policy isolation, quota utilization cost, warmup exclusion, raw outputs, seed reproducibility |

Before the new comparison, 60 cases passed. After adding the policy benchmark
and reporting regression tests, **76 cases passed** (3.85 seconds in the final
run). The environment emits
one FastAPI/Starlette `httpx` deprecation warning; this is not a failed test.

A passing suite establishes that these tested scenarios behaved as expected.
It does not prove security, coverage of every transcript field, resistance
to every replay strategy, absence of concurrency bugs, or paper compatibility.

## 13. Every source file: what to study and why

The annotated source is the line-by-line companion. Work through files in
the following order rather than alphabetically.

| File | Responsibility and points to explain |
|---|---|
| `settings.py` | Environment defaults, integer parsing, invalid parameter rejection |
| `qkd_mock/pool.py` | Refill arithmetic, lock, issue/retrieve accounting |
| `qkd_mock/models.py` | JSON schemas and request limits |
| `qkd_mock/server.py` | Application factory, routes, status/error conversion |
| `qkd_mock/client.py` | REST calls, identity header, Base64 decoding |
| `crypto/kem.py` | Algorithm allowlist, lazy native import, key-pair container, KEM calls |
| `crypto/kdf.py` | Field framing, HKDF extract/expand, labels, ROKDF, HMAC |
| `protocol/combiner.py` | Older labelled-HKDF prototype and explicit mode enum |
| `mitigations/mitigations.py` | Rolling quota history, injected clock, static admission check |
| `protocol/hake.py` | Alice/Bob state, four messages, QKD policy, transcript and confirmation |
| `crypto/store.py` | Older JSON key registry, distinct from file-demo provisioning |
| `transfer/identity.py` | Pinned identities, role/algorithm validation, filesystem permissions |
| `transfer/wire.py` | Canonical JSON, strict Base64, size-bounded TCP framing |
| `transfer/handshake.py` | Encodes/decodes HAKE tuples and adapts HTTP KME callbacks |
| `transfer/channel.py` | Directional HKDF/AES-GCM keys, nonce counters, authenticated context |
| `transfer/storage.py` | Validates offers and publishes only verified complete files |
| `transfer/queue.py` | SQLite transactions, durable metadata, exclusive worker and recovery |
| `transfer/audit.py` | Structured allowed metadata and append-only local log writes |
| `transfer/sender.py` | Source validation, fresh handshake, offer/file/receipt, state transitions |
| `transfer/receiver.py` | Threaded server, authentication, verified publish, receipt/error handling |
| `transfer/verification.py` | Starts real processes, runs five scenarios, compares files, records evidence |
| `transfer/cli.py` | Transfer command arguments, dispatch, exit-code meanings |
| `benchmarks/runner.py` | Small prototype-combiner smoke timer and CSV |
| `benchmarks/suite.py` | Real in-process KEM benchmark plus virtual-time depletion sweep |
| `benchmarks/policies.py` | Paired policy scheduling, actual guard timers, mode/accounting/fairness outputs |
| `benchmarks/policy_report.py` | Aggregates recorded events, builds outcome figure and HTML tables |
| `benchmarks/plot_wp6.py` | Existing depletion figures; see supply-grouping caveat below |
| `benchmarks/plot_performance_figures.py` | Groups raw timing CSV, plots median/p95 and field sizes |
| `cli.py` | Main command parser/dispatcher and small demo |
| `__init__.py` files | Package markers/documentation; no hidden protocol logic |
| `tests/*.py` | Executable specifications of expected behavior and rejection paths |
| `docs/architecture/generate_architecture.py` | Draws six architecture plates with ReportLab, exports PDF/SVG |
| `docs/architecture/run_verification.py` | Older command orchestration and REST-backed handshake checks |
| `Makefile` | Short aliases for setup, tests, server, demos and cleanup |
| `pyproject.toml` | Dependencies, extras, package discovery, console entry point, pytest settings |
| `Dockerfile` / `docker-compose.yml` | Container build and default smoke command |
| `configs/experiments.json` | Design matrix; original benchmark does not load this automatically |

### Python details that often cause viva questions

`self.x` is state belonging to one object. Alice saves intermediate secrets
because later methods need them. A constructor does not complete the
handshake; callers must follow the method order.

`bytes | None` is a type annotation permitting either binary data or missing
data. It is not runtime validation by itself. `tuple[bytes, bytes]` describes
two return values. `-> None` means no meaningful return value.

`@dataclass` generates record-like methods. `frozen=True` prevents ordinary
field reassignment; it does not zero memory or protect files. `slots=True`
restricts per-instance attribute storage. `NamedTuple` supports immutable
tuple-like results with named fields.

`with` enters a context manager and guarantees its exit logic runs. It is
used for locks, files, liboqs handles, database transactions, and workers.
`try/except` separates expected failure paths. `finally` runs even if an
exception occurs. `raise ... from exc` preserves the causal exception.

`@staticmethod` means no instance argument is required. `@classmethod`
receives the class, used for alternate construction such as `from_env`.
`yield` in context-manager fixtures separates setup from cleanup.

List/dict comprehensions transform collections. `Counter` counts labels;
`defaultdict(list)` creates a list when a new peer is first seen. `**fields`
expands a dictionary into keyword arguments. `*fields` accepts/expands a
variable number of positional values. `f'...'` interpolates values into text.

`b'...'` is a byte literal, not ordinary text. `.encode()` turns text into
bytes; `.decode()` reverses an encoding. `.hex()` and Base64 are reversible
representations, not protection. `bytes(32)` means 32 zero bytes, so it must
not be confused with a fresh random key.

`if __name__ == '__main__'` runs the CLI when invoked as a program, while
allowing functions to be imported elsewhere. Commented-out historical code
at the end of `cli.py` and `suite.py` does not execute.

## 14. Claims to correct before making slides

Several old status documents describe an earlier or more ambitious state.
Use inspected behavior and the new evidence when they conflict.

* **Paper-exact implementation:** unverified. The ePrint abstract and metadata
  were accessible; full PDF retrieval was blocked during this review. No
  line-by-line protocol correspondence was established. Say “research
  implementation inspired by the cited signature-free hybrid AKE design.”
* **“17 tests”:** obsolete; use the final executed count.
* **“Full handshake uses HKDF-SHA3-256”:** incorrect for the active path;
  distinguish the prototype, ROKDF handshake, and transfer HKDF-SHA256.
* **“Measured network bytes”:** the existing benchmark sums raw fields.
* **“QKD means unconditional file secrecy”:** not established for this mock,
  KDF, authentication model, or AES-GCM application.
* **“5% threshold reserves priority sessions”:** there is no priority class
  scheduler here. It checks occupancy and rejects/degrades by policy.
* **“All mitigations already have measured costs”:** now resource and local
  guard costs are compared; concurrent end-to-end costs remain future work.
* **“Quota is enforced globally”:** only a reused manager sees repeated
  requests. The benchmark's fresh per-session managers do not provide a
  global limiter. The file Sender shares a manager within that process;
  separate CLI processes do not share its history.
* **“A proof is included”:** `docs/security_analysis.md` is an informal outline.
  Its QKD-mock/randomness hop and unconditional equalities are not a formal
  reduction. Its freshness conditions do not fully address the stated state-
  reveal powers; MAC unforgeability is not the same as encryption IND-CPA.
  Its information-theoretic entries are inconsistent and need formal review.
* **“The burst plot separates each supply”:** `plot_wp6`'s first figure groups
  by rate/depth and averages across supply values. Do not interpret one such
  curve as a specified supply rate. Use the source CSV or separate-supply
  policy figure when the distinction matters.
* **“Config file changes drive experiments”:** original suite parameters are
  hardcoded/CLI-driven; it does not load `configs/experiments.json`.

Other known limits include non-atomic HTTP status/acquire, broad acquisition
exception handling, no distributed quota store, no issued-key expiry, no
guaranteed secret erasure, and minimal handshake-state misuse checks.
These are appropriate future-work points for research software.

## 15. A seminar plan you can rehearse

For a 25–30 minute slot:

| Time | What to explain |
|---|---|
| 0–2 min | Problem: a finite QKD resource can bottleneck fast handshakes |
| 2–6 min | KEM, QKD/KME/SAE, MAC, KDF, and the trust assumptions |
| 6–11 min | Walk through the four messages; identify which values are secret |
| 11–14 min | Derive 39.0625 keys/s and 2.10-second depletion example |
| 14–19 min | Show the policy outcomes and explain the quota utilization cost |
| 19–23 min | Demonstrate hybrid, explicit fallback and tamper rejection |
| 23–26 min | Testing evidence and limitations; distinguish model from hardware |
| Remaining | Questions; use code annotations as your technical appendix |

For a longer slot, add the queue/receipt-loss example, timing methodology,
and a live source walkthrough. Do not try to read thousands of lines aloud.
Learn every module, but present the causal flow and keep detailed code for
questions.

Rehearse the commands in the exact environment before the seminar. Have the
saved verification report and figures available if a live service cannot
start. Show a status endpoint or an audit row, not a raw key-delivery response.

## 16. Likely questions and defensible answers

**What is novel here?** The project's contribution is a reproducible study of
finite QKD supply and policy behavior in a working hybrid-exchange testbed.
Do not assert world-first novelty without a separate literature review.

**Are you implementing quantum cryptography?** We simulate the KME's finite
key resource and delivery API. The cryptographic KEM operations are real
native library operations; the quantum physical link is not implemented.

**Why remove signatures?** This design uses long-term KEM keys and keyed
confirmation messages for authentication. It still requires authentic
public-key provisioning; signature-free is not trust-free.

**Why use both KEM and QKD?** To investigate a hybrid that combines different
sources of secret material and can potentially hedge assumptions. Security
under component compromise depends on the combiner, authentication, and
threat model; it is not automatic merely because two inputs are present.

**Does PQC-only mean insecure?** It means the QKD component is absent and
security rests on the computational protocol assumptions. It may violate an
application's hybrid-required policy, even if PQC is otherwise acceptable.

**Why is the QKD ID public?** It selects a shared key at the KME; it is not
the secret. Correct access control must prevent unauthorized retrieval.
The local header-based mock does not supply production access control.

**Why 256 bits per handshake?** That is the testbed's chosen QKD input size,
enforced by the active handshake. Different designs could consume different
amounts; the throughput formula must use their actual consumption.

**Why not increase the pool?** More stored keys absorb a longer burst, but
cannot sustain demand above the refill rate indefinitely.

**Which mitigation wins?** It depends on the objective. Fallback maximizes
modeled completion with explicit mode reduction. Admission preserves a
hybrid-only success policy at availability cost. Quotas constrain individual
peers but can waste capacity if fixed poorly. The experiment measures this
tradeoff rather than declaring a universal winner.

**Do quotas improve fairness?** Specify the fairness metric. Equal caps can
improve absolute allocation balance while reducing equality of success
fractions under unequal demand. We report per-peer outcomes and name our
Jain-index definition.

**Why is admission occupancy below 5% in the report?** The check is before
consuming one key. Seven of 128 passes; afterward six remain.

**Does a passing test suite prove CK01 security?** No. It demonstrates tested
functional behavior. A formal AKE proof needs a precise game, freshness,
trust assumptions, and reductions tied to the exact implementation/design.

**What happens if the KEM breaks?** The intended hybrid benefit depends on
QKD secrecy and on whether authentication and key delivery survive that
compromise. It is unsafe to promise active-attack security from an informal
“one component survives” slogan.

**Can you reproduce the timing exactly?** The workload and settings can be
reproduced; CPU timings vary with host, native library, load, caches, and
frequency scaling. We retain raw samples and environment/source metadata.

**Is the full handshake faster with QKD in some results?** Tiny signed
differences can be measurement variation. The benchmark uses a fixed local
QKD callback, not a real networked QKD service.

**What if Alice loses Bob's acknowledgement?** The file may already exist at
Bob. Alice records `UNKNOWN` and does not blindly resend.

**What would you implement next?** Policy-aware concurrent end-to-end load
tests, atomic admission, shared quotas, stronger pool accounting/expiry,
more transcript-binding regression tests, and protocol/proof correspondence
review against the complete paper.

## 17. Your study order

First explain the system in one minute without reading. Then derive the
throughput equation and trace the four messages on paper. Next run the
five-case application demo and explain every resulting state. After that,
read the annotated source module by module and use the tests to check your
understanding. Finally rehearse the questions above with the raw CSV/report
open, so you can distinguish observed results from assumptions.
