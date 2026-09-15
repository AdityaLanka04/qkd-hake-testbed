# Hybrid QKD-PQC HAKE Testbed

This is the starter workspace for the course project **Hybrid QKD-PQC
Authenticated Key Exchange without Digital Signatures**.

The current version contains:

- an in-memory ETSI GS QKD 014-style key pool;
- `Get status`, `Get key`, and `Get key with key IDs` endpoints;
- configurable refill rate, pool depth, key size, and per-peer quota;
- a labelled HKDF-SHA3-256 combiner;
- explicit `HYBRID_QKD`, `PQC_ONLY`, and `REJECTED` security states;
- a liboqs-python adapter ready for ML-KEM and FrodoKEM;
- basic unit tests and experiment configuration.

It does **not** yet claim to implement the exact 2026 paper protocol. The final
message sequence and labels must be transcribed and reviewed against the paper.

## Quick start

```bash
make setup
make test
make demo
```

Start the mock KME:

```bash
make server
```

It listens on `http://127.0.0.1:8000` by default. Example request:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/keys/bob/enc_keys \
  -H 'Content-Type: application/json' \
  -H 'X-SAE-ID: alice' \
  -d '{"number":1,"size":256}'
```

Bob retrieves the same key by sending the returned ID to:

```text
POST /api/v1/keys/alice/dec_keys
X-SAE-ID: bob
{"key_IDs":[{"key_ID":"..."}]}
```
## Docker

Docker provides a reproducible environment for running the QKD-HAKE
testbed and its experiments.

Build the Docker image:

```bash
docker build -t qkd-hake-testbed .

Run the demo with Docker Compose:
docker compose up

Run the complete test suite inside Docker:
docker compose run --rm qkd-hake python -m pytest -q

Run the 1000-run benchmark suite:
docker compose run --rm qkd-hake python -m qkd_hake.cli benchmark

The Docker image includes the required build tools and liboqs environment

needed by liboqs-python, allowing the PQC KEM tests and benchmarks to run

without requiring a local liboqs installation.

```

## Configuration

Environment variables used by the mock KME:

| Variable | Default | Meaning |
|---|---:|---|
| `QKD_REFILL_BPS` | `10000` | Generated QKD bits per second |
| `QKD_POOL_DEPTH` | `128` | Maximum number of stored keys |
| `QKD_INITIAL_KEYS` | `128` | Keys available at startup |
| `QKD_KEY_SIZE_BITS` | `256` | Size of one QKD key |
| `QKD_PER_PEER_QUOTA` | `0` | Outstanding keys per peer; 0 disables quota |

## Repository layout

```text
src/qkd_hake/qkd_mock/   mock QKD KME and pool accounting
src/qkd_hake/crypto/     labelled HKDF and liboqs adapter
src/qkd_hake/protocol/   security modes and key combiner
src/qkd_hake/benchmarks/ benchmark code to be expanded
configs/                 reproducible experiment matrix
tests/                   unit and API tests
```

## Research caution

This repository is for controlled experiments. Do not deploy it to protect
real traffic. The server currently uses a test header to identify an SAE;
production ETSI deployments require authenticated channels and proper access
control.
