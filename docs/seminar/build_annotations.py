"""Build an offline, line-numbered companion to the manually authored seminar guide.

Only source/configuration files are read. Runtime keys, identities, and payloads
are never scanned. Explanations combine syntax-tree descriptions with curated
module, function, variable and security notes. Rebuild after changing source.
"""
from __future__ import annotations

import ast
from html import escape
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/seminar'

MODULES = {
    'settings.py': 'Reads environment configuration and rejects negative values, zero capacity, incompatible key sizes, and excessive initial occupancy.',
    'qkd_mock/pool.py': 'Finite available-key inventory with lazy refill. Issuance consumes inventory; peer retrieval removes a pending key without replenishing inventory. Uses software randomness, not quantum hardware. Duplicate IDs within one retrieval request remain an accounting edge case.',
    'qkd_mock/models.py': 'Pydantic models define the HTTP request/response shape. Type annotations here participate in runtime validation through BaseModel; ordinary Python annotations alone do not.',
    'qkd_mock/server.py': 'FastAPI routes adapt HTTP requests to a shared QKDKeyPool. X-SAE-ID is an unauthenticated local test identity. This is ETSI-style delivery, not a conformant authenticated production KME.',
    'qkd_mock/client.py': 'Synchronous HTTP adapter used by real transfer sessions. It raises HTTP errors and Base64-decodes returned material. QKD acquisition is fixed to 256 bits.',
    'crypto/kem.py': 'Thin wrapper around liboqs-python. Native liboqs implements KEM math. Every with-block releases the native context, but exported Python secret bytes have no guaranteed erasure.',
    'crypto/kdf.py': 'Contains two distinct derivation paths: labelled HKDF-SHA3-256 helpers for the prototype, and SHA3-512 ROKDF plus HMAC-SHA256 for the active handshake. A function name/docstring is not proof of correspondence to a paper.',
    'crypto/store.py': 'Older plaintext JSON identity store, not used for file-demo provisioning. Does not implement the permissions/no-overwrite behavior of transfer/identity.py. Never print its loaded values.',
    'protocol/combiner.py': 'Prototype HKDF combiner used by the smoke demo. Not called by the four-message HAKE. qkd_key=None and qkd_key=b"" are treated differently; the latter is a known missing-validation limitation here.',
    'protocol/hake.py': 'Active four-message Alice/Bob implementation. Study in execution order: Alice.message1, Bob.message2, Alice.message3, Bob.message4, Alice.derive_and_verify. Transcript-bound modes and validated QKD delivery are central. Paper-exact correspondence is unverified.',
    'mitigations/mitigations.py': 'In-process sliding request quota and pre-request 5% admission check. Quota history must be shared across sessions to enforce a cross-session limit. The optional clock lets the policy experiment use deterministic virtual time.',
    'transfer/identity.py': 'Creates out-of-band pinned Alice/Bob identities; role files contain private material and must not be shared. Provisioning uses private permissions and refuses overwrite.',
    'transfer/wire.py': 'Canonical JSON, strict Base64 and bounded TCP frames. A four-byte network-order length precedes each JSON object. TCP recv can return fewer bytes than requested, so _read loops.',
    'transfer/handshake.py': 'Converts HAKE tuples into JSON network frames and invokes the real HTTP KME client. Maps the internal degraded mode to the application label PQC_ONLY.',
    'transfer/channel.py': 'Derives directional AES-GCM keys from the HAKE key. Sequence numbers become nonces and authenticated context binds direction, type and transcript. Files are encrypted here, not in the KEM wrapper.',
    'transfer/storage.py': 'Validates policy, filename, UUID, size and digest. Only authenticated, length/digest-verified plaintext is published. Hard links prevent overwriting an existing destination.',
    'transfer/queue.py': 'SQLite queue stores references and metadata rather than keys or payload copies. An exclusive Unix worker lock prevents duplicate local processing. Interrupted in-flight sends become UNKNOWN.',
    'transfer/audit.py': 'Writes allowed event metadata to a JSON-lines log. Secrets are excluded by the field interface. Files use private creation permissions; writes are serialized within this Audit object.',
    'transfer/sender.py': 'Validates queued source, performs fresh handshake, sends encrypted metadata/file, validates receipt, and classifies results. A possible post-send failure becomes UNKNOWN instead of automatic retry.',
    'transfer/receiver.py': 'Threaded loopback TCP receiver. Verifies handshake, encrypted offer and file, then atomically publishes and acknowledges. A lost acknowledgement after publication is logged separately.',
    'transfer/cli.py': 'Defines transfer subcommands and translates outcomes into shell exit codes: 0 complete, 2 pending queue, 1 failed/unknown. Receiver binds only to loopback.',
    'transfer/verification.py': 'Functional five-scenario harness using actual subprocesses and loopback sockets. Generates private identity files, public evidence and a reproducible dataset fixture. Timing here is one-run functional evidence, not a benchmark distribution.',
    'benchmarks/runner.py': 'Smoke timing of the older prototype combiner using fixed fixture secrets. No KEM, network, or full HAKE timing occurs here.',
    'benchmarks/suite.py': 'Two independent experiments: paired in-process actual KEM handshakes, and virtual-clock pool depletion. The performance callback uses fixed QKD material. Field-byte counts exclude actual transport encoding. Commented old implementations do not execute.',
    'benchmarks/policies.py': 'New paired resource-policy comparison. Every policy sees identical seeded arrivals. It uses actual pool/check logic and real guard/decision timers, but does not execute KEMs or network handshakes. CSVs contain metadata only.',
    'benchmarks/policy_report.py': 'Reads policy CSV evidence and derives tables and figures. Timing percentiles pool raw events across repeats. Fairness in the report is the mean of per-repeat indices, explicitly labeled.',
    'benchmarks/plot_wp6.py': 'Plots original depletion CSVs. The first plot groups by rate and depth but omits supply, averaging supply values together; do not describe it as a separate supply-specific curve.',
    'benchmarks/plot_performance_figures.py': 'Reads the real performance CSV with pandas, computes group median/p95 and plots them. Log axes make Frodo and ML-KEM visible together. Plot labels saying serialized/wire bytes refer to the benchmark raw-field sum.',
    'cli.py': 'Main argparse entry point. Dispatches server, demo, benchmark, sweep, policy-sweep and transfer. The bottom commented-out earlier CLI is inactive historical text.',
    'docs/architecture/generate_architecture.py': 'ReportLab drawing/export helper for six PDF/SVG architecture plates. Drawing constants and text are presentation instructions, not executed cryptographic behavior. Historical dates/claims belong to that generated atlas snapshot.',
    'docs/architecture/run_verification.py': 'Older command runner records tests, demos, experiments and real REST-backed HAKE checks. It uses a fixed 2026-10-06 output path, so rerunning may replace historical outputs.',
}

FUNCTIONS = {
    'message1': 'Encapsulates to Bob’s trusted long-term public key. Returns ciphertext and Alice nonce; preserves k1 locally for later authentication.',
    'message2': 'Bob recovers k1, creates his ephemeral KEM pair, encapsulates k2 to Alice, and authenticates the response with tau1.',
    'message3': 'Alice verifies tau1 first, obtains k2 and k_star, applies resource policy, validates delivered QKD material, and generates tau2.',
    'message4': 'Bob verifies tau2, decapsulates the ephemeral secret, retrieves QKD by ID, constructs transcript/KDF inputs and sends final confirmation tau3.',
    'derive_and_verify': 'Alice independently reconstructs transcript/KDF inputs and verifies tau3 before returning the session key and explicit mode.',
    'validate_qkd_key': 'Rejects non-bytes, missing/empty/wrong-length QKD material and missing key IDs. Active HAKE requires 32 bytes.',
    '_refill_locked': 'Converts elapsed-time bit production into whole available keys, retaining fractional credit and discarding surplus beyond capacity. Caller must hold the lock.',
    'issue': 'In the pool: checks quota and availability before generating keys, deducting available inventory and recording pending peer retrieval. Server helper of the same name converts errors to HTTP responses.',
    'retrieve': 'In the pool: verifies lookup presence, removes pending keys, and reduces outstanding count. This does not refill available inventory. The server helper translates lookup errors.',
    'check_quota': 'Prunes timestamps at least one second old, rejects when the count reaches the cap, otherwise records this admitted check. Does not wait or allocate a key.',
    'check_admission_control': 'Raises below 5% current occupancy; exactly 5% is accepted. The check occurs before a subsequent consumption.',
    'rokdf': 'Hashes a fixed label and four framed inputs with SHA3-512 to produce 64 bytes. The active handshake splits the output into two 32-byte keys.',
    'serialize_fields': 'Converts each text field to UTF-8 and prefixes every byte field with its four-byte length. Preserves field boundaries.',
    'hkdf_extract': 'HMAC-SHA3-256 extraction; an absent salt is represented by a hash-length all-zero salt, not by inventing a missing secret key.',
    'hkdf_expand': 'Computes chained HMAC output blocks with info and a one-byte counter, up to the HKDF 255-block limit, then truncates.',
    'derive_keys': 'Prototype labelled extract/expand chain. Produces separate session/client-confirmation/server-confirmation outputs and a mode enum.',
    'generate_keypair': 'Asks native liboqs to generate a fresh KEM public/private pair and exports it to a Python record.',
    'encapsulate': 'Calls native encapsulation with the supplied public key; returns ciphertext and secret as separate values.',
    'decapsulate': 'Calls native decapsulation using the private key and received ciphertext.',
    'provision': 'Creates pinned peer public-key relationships and private local identity files exactly once.',
    'seal': 'Encrypts/authenticates one record with the send-direction key and next 96-bit sequence nonce.',
    'open': 'For SecureChannel: rejects unexpected type/sequence, decrypts/authenticates using receive-direction context, increments only after success.',
    'publish_file': 'Checks plaintext length/digest then writes, flushes and atomically links a temporary file into a no-overwrite destination.',
    'attempt': 'Performs one queued file attempt and records DELIVERED, QUEUED, FAILED or UNKNOWN according to the stage and error.',
    'worker': 'Acquires a nonblocking exclusive queue lock and marks abandoned in-flight work UNKNOWN before yielding control.',
    'np_percentile': 'Computes a sorted, linearly interpolated percentile; p95 is not a confidence level.',
    'run_performance_benchmarks': 'Per algorithm: provisions static keys, warms both modes, alternates paired order, times actual local HAKE operations, checks key equality and writes raw measurements.',
    'sweep_bottleneck_analysis': 'Uses periodic virtual arrivals to measure first pool failure, then resource success after depletion, without running KEMs or network traffic.',
    'decide': 'Evaluates one isolated policy guard, then consumes/retrieves a key or emits explicit PQC_ONLY/REJECTED. Times local work, not a handshake.',
    'peer_schedule': 'Creates a seeded categorical peer assignment; it does not seed cryptographic randomness.',
    'jain_index': 'Computes squared sum divided by n times sum of squares. Here inputs are per-peer hybrid success fractions.',
    'run_case': 'Runs one policy against the shared deterministic arrival model; warmup affects state but is excluded from emitted measurements.',
    'run_policy_comparison': 'Validates configuration, creates a new output directory, executes paired policy cases and writes evidence/source metadata.',
    'build_report': 'Aggregates recorded policy outcomes and raw guard timings, then writes a figure, aggregate CSV and HTML report.',
}

VARIABLES = {
    'k1': 'secret associated with encapsulation to Bob’s static public key',
    'k2': 'secret associated with encapsulation to Alice’s static public key',
    'k_star': 'secret associated with Bob’s ephemeral KEM key',
    'ct1': 'public KEM ciphertext sent in message 1',
    'ct2': 'public KEM ciphertext sent in message 2',
    'ct_star': 'public ephemeral-KEM ciphertext sent in message 3',
    'pk_e': 'Bob’s ephemeral public key',
    'kp_e': 'Bob’s ephemeral public/private key pair',
    'tau1': 'Bob’s message-2 MAC under k1',
    'tau2': 'Alice’s message-3 MAC under k2',
    'tau3': 'Bob’s final confirmation MAC under the derived confirmation key',
    'k1h': 'first 32 output bytes, used for confirmation',
    'k2h': 'last 32 output bytes, used as the session key',
    'k_h': '64-byte SHA3-512 derivation result',
    'k_qkd': 'delivered 32-byte QKD input, or None only for an explicitly degraded path',
    'qkd_key_id': 'public reference to the shared QKD input',
    'sigma_qkd': 'QKD KDF input; empty only after explicit fallback selection',
    'raw_transcript': 'length-framed handshake context, including identities and mode',
    'transcript_hash': 'digest binding the local view of the handshake context',
    'c_kem': 'KDF context carrying identities, keys, KEM secrets and transcript digest',
    'c_qkd': 'KDF context carrying identities, QKD ID and transcript digest',
    '_available': 'unissued QKD inventory; retrieval does not increase it',
    '_fractional_bits': 'refill credit not yet converted to accepted complete keys',
    '_issued': 'pending keys indexed by directed identities and key ID',
    '_outstanding': 'counts of pending keys by directed pair',
    'send_sequence': 'next send-direction record number/nonce',
    'recv_sequence': 'next expected receive-direction record number/nonce',
    'data_started': 'whether a failed send may already have delivered file bytes',
    'committed': 'whether Bob has already published the verified file',
    'security_mode': 'explicit hybrid versus degraded outcome bound into the transcript',
    'sustainable_rate': 'modeled supply divided by bits per key',
    'theoretical_burst_duration': 'continuous approximation depth/(demand minus supply)',
    'bytes_on_wire': 'sum of raw handshake fields, excluding JSON/Base64/transport/KME traffic',
}


def short(node: ast.AST | None, limit: int = 180) -> str:
    if node is None:
        return 'None'
    value = ast.unparse(node)
    return value if len(value) <= limit else value[:limit] + '…'


def expression(node: ast.AST | None) -> str:
    if node is None:
        return 'no value'
    if isinstance(node, ast.Call):
        name = short(node.func)
        special = {
            'secrets.token_bytes': 'fresh cryptographically generated software random bytes',
            'uuid.uuid4': 'a fresh random UUID identifier',
            'time.perf_counter_ns': 'the high-resolution elapsed-time counter in nanoseconds',
            'time.process_time_ns': 'process CPU usage in nanoseconds',
            'time.monotonic': 'a monotonic clock reading in seconds',
            'time.time': 'wall-clock epoch seconds',
            'hashlib.sha3_256': 'a SHA3-256 hash object over the specified bytes',
            'hashlib.sha3_512': 'a SHA3-512 hash object over the specified bytes',
            'hashlib.sha256': 'a SHA-256 hash object over the specified bytes',
            'hmac.compare_digest': 'a timing-resistant equality check of the supplied tags',
            'serialize_fields': 'unambiguous length-prefixed serialization of the supplied fields',
            'hmac_sha256_tag': 'a keyed HMAC-SHA256 tag over the specified message',
            'rokdf': 'a 64-byte hash-derived combination of KEM/QKD inputs and context',
            'statistics.median': 'the middle value of sorted observations (mean of two middle values when even)',
            'statistics.mean': 'the arithmetic average of observations',
            'np_percentile': 'a linearly interpolated percentile of sorted observations',
            'base64.b64encode': 'a reversible Base64 encoding, not encryption',
            'base64.b64decode': 'decoded binary bytes from Base64 text',
            'json.loads': 'a Python value parsed from JSON',
            'json.dumps': 'a JSON text representation',
            'len': 'the length/count of ' + (short(node.args[0]) if node.args else 'the supplied object'),
            'int': 'an integer conversion (truncation toward zero for a float)',
            'float': 'a floating-point numeric conversion',
            'str': 'a text conversion',
            'list': 'a new list containing the supplied iterable',
            'tuple': 'a tuple containing the supplied iterable',
            'sorted': 'a sorted copy of the supplied iterable',
            'sum': 'the sum of the supplied values',
            'min': 'the smallest supplied value',
            'max': 'the largest supplied value',
        }
        if name in special:
            return special[name]
        if name.endswith('.digest'):
            return 'the binary digest/tag from the hash or HMAC object'
        if name.endswith('.hexdigest'):
            return 'the digest encoded as hexadecimal text'
        if name.endswith('.encapsulate'):
            return 'a KEM ciphertext and shared secret from encapsulation to the supplied public key'
        if name.endswith('.decapsulate'):
            return 'the KEM shared secret recovered with the supplied private key and ciphertext'
        if name.endswith('.generate_keypair'):
            return 'a fresh KEM public/private pair'
        if name.endswith('.encode'):
            return 'encoded bytes for the text (UTF-8 unless otherwise specified)'
        if name.endswith('.to_bytes'):
            return 'a fixed-length integer byte encoding with the specified byte order'
        if name.endswith('.pop'):
            return 'the removed mapping/list entry; this mutates its container'
        if name.endswith('.encrypt'):
            return 'AEAD ciphertext plus tag under the supplied nonce and associated data'
        if name.endswith('.decrypt'):
            return 'authenticated plaintext, or an exception when AEAD verification fails'
        return 'the result of calling ' + name + '(' + ', '.join(short(a, 55) for a in node.args[:4]) + (', …' if len(node.args) > 4 else '') + ')'
    if isinstance(node, ast.BinOp):
        ops = {ast.Add: 'plus/concatenated with', ast.Sub: 'minus', ast.Mult: 'multiplied by (or repeated by)',
               ast.Div: 'divided by', ast.FloorDiv: 'integer-divided by', ast.Mod: 'modulo', ast.Pow: 'to the power of', ast.BitXor: 'XORed with', ast.BitOr: 'combined with |'}
        return short(node.left, 95) + ' ' + ops.get(type(node.op), 'combined with') + ' ' + short(node.right, 95)
    if isinstance(node, ast.IfExp):
        return short(node.body, 80) + ' when ' + short(node.test, 100) + ', otherwise ' + short(node.orelse, 80)
    if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
        return 'a comprehension that transforms/filters items: ' + short(node)
    if isinstance(node, ast.Dict):
        return 'a mapping with fields ' + ', '.join(short(key, 35) for key in node.keys[:10]) + (' …' if len(node.keys) > 10 else '')
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return 'a ' + type(node).__name__.lower() + ' containing ' + ', '.join(short(item, 65) for item in node.elts[:5]) + (' …' if len(node.elts) > 5 else '')
    if isinstance(node, ast.Lambda):
        return 'an inline callback returning ' + short(node.body)
    if isinstance(node, ast.Subscript):
        return 'the selected item/slice ' + short(node)
    if isinstance(node, ast.JoinedStr):
        return 'formatted text with runtime values substituted: ' + short(node)
    return short(node)


def explain(node: ast.stmt) -> str:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if isinstance(node, ast.ImportFrom) and node.module == '__future__':
            return 'Postpone evaluating type annotations; this is Python typing behavior, not cryptography.'
        return 'Import dependencies used below: ' + ', '.join(alias.name + (' as ' + alias.asname if alias.asname else '') for alias in node.names) + '.'
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        purpose = FUNCTIONS.get(node.name)
        if node.name.startswith('test_'):
            purpose = 'Executable regression scenario: ' + node.name[5:].replace('_', ' ') + '. Assertions below state the expected outcome.'
        return 'Define ' + node.name + '(). ' + (purpose or 'The indented body runs when called; arguments and return annotations describe its interface. See the module overview and individual statements below.')
    if isinstance(node, ast.ClassDef):
        return 'Define class ' + node.name + (' inheriting from ' + ', '.join(short(base) for base in node.bases) if node.bases else '') + '. Its methods share per-instance state through self; class-level definitions run during construction of the class.'
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = ', '.join(short(target) for target in targets)
        value = node.value
        message = ('Declare ' + names + ' with annotation ' + short(node.annotation) + '.' if value is None else 'Set ' + names + ' to ' + expression(value) + '.')
        for target in targets:
            final = short(target).split('.')[-1]
            if final in VARIABLES:
                message += ' Meaning: ' + VARIABLES[final] + '.'
        return message
    if isinstance(node, ast.AugAssign):
        return 'Update ' + short(node.target) + ' in place using ' + type(node.op).__name__ + ' with ' + short(node.value) + '. This changes the existing state/counter.'
    if isinstance(node, ast.Return):
        return 'Return ' + expression(node.value) + ' to the caller and stop this function.'
    if isinstance(node, ast.Raise):
        return 'Abort this path by raising ' + short(node.exc) + ('; preserve the underlying cause ' + short(node.cause) if node.cause else '') + '.'
    if isinstance(node, ast.Assert):
        return 'Require ' + short(node.test) + ' to be true; otherwise raise AssertionError. This is a test/check, not a cryptographic proof.'
    if isinstance(node, ast.If):
        return 'Run this branch only if ' + short(node.test) + ' is true; otherwise consider its else/elif branch.'
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return 'For each ' + short(node.target) + ' from ' + expression(node.iter) + ', execute the indented body.'
    if isinstance(node, ast.While):
        return 'Repeat the indented body while ' + short(node.test) + ' remains true; break/return/error may end it earlier.'
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return 'Enter managed context(s): ' + '; '.join(short(item.context_expr) + (' as ' + short(item.optional_vars) if item.optional_vars else '') for item in node.items) + '. Cleanup/exit runs even if the body raises.'
    if isinstance(node, ast.Try):
        return 'Attempt the indented operations; matching except blocks handle errors, else handles success, and finally performs mandatory cleanup where present.'
    if isinstance(node, ast.Expr):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return 'Documentation string. It describes author intent; verify claims against the executable code and seminar caveats.'
        if isinstance(node.value, ast.Yield):
            return 'Yield ' + expression(node.value.value) + ' to the caller; resume afterward for cleanup in this context manager/fixture.'
        return 'Execute ' + expression(node.value) + '; any effects occur even when the return value is discarded.'
    if isinstance(node, ast.Pass):
        return 'No operation. Used for an empty exception class or an intentionally empty handled branch.'
    if isinstance(node, ast.Break):
        return 'Exit the nearest loop immediately.'
    if isinstance(node, ast.Continue):
        return 'Skip the remaining body of this iteration and proceed to the next loop item.'
    if isinstance(node, ast.Delete):
        return 'Delete the selected binding/item: ' + ', '.join(short(target) for target in node.targets) + '.'
    if isinstance(node, (ast.Nonlocal, ast.Global)):
        return 'Use the enclosing/global binding for ' + ', '.join(node.names) + ' rather than create a new local binding.'
    return 'Python ' + type(node).__name__ + ' statement: ' + short(node)


def special_note(text: str) -> str:
    notes = [
        ('self.ct1 + ct2', 'This short MAC context is not the full canonical transcript; the full context is serialized later.'),
        ('self.ct1 + self.ct2', 'This is the concatenated pair of static KEM ciphertexts used in early MACs.'),
        ('if self.k_qkd is not None else b""', 'The empty KDF field is permitted only after the explicit degraded mode decision; malformed hybrid delivery was rejected earlier.'),
        ('if k_qkd is not None else b""', 'Bob must reject failed retrieval for a nonempty ID; only the explicit no-ID degraded path reaches the empty field.'),
        ('self.peer_request_history[peer_id].append(now)', 'Quota records an admitted request check, even if acquisition later fails; it is not a count of successful sessions.'),
        ('(stored_keys / max_keys) < 0.05', 'Exactly 5% passes. The following key consumption can take occupancy below 5%.'),
        ('self._issued.pop(item)', 'Repeated IDs in the same request can fail after a prior pop; presence checking does not deduplicate the list.'),
        ('qkd_key = b"q" * 32', 'Fixed benchmark/test fixture only. This does not model fresh physical QKD generation.'),
        ('pool.issue(', 'Issuance consumes available inventory. In a pool-only sweep no HAKE is executed.'),
        ('b"A"', 'Preserve this exact early-MAC label in explaining the implementation; it is not a variable.'),
        ('b"B"', 'Preserve this exact early-MAC label in explaining the implementation; it is not a variable.'),
        ('security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"', 'The downgrade is explicit and later transcript-bound; application display maps this to PQC_ONLY.'),
        ('time.sleep(', 'Real waiting occurs here; it differs from advancing a SimulatedClock.'),
        ('secret_key_hex', 'Private key persistence, not a safe log field. Do not display the runtime JSON contents.'),
        ('os.link(temporary, target)', 'Atomic no-overwrite publication on the same filesystem. An existing target raises rather than being replaced.'),
        ("state = 'UNKNOWN' if data_started", 'Once file sending begins, a lost receipt cannot prove non-delivery; avoid automatic duplicate retries.'),
    ]
    return ' '.join(note for pattern, note in notes if pattern in text)


def annotations(path: Path) -> tuple[list[tuple[int, str, str]], list[dict]]:
    source = path.read_text()
    tree = ast.parse(source)
    statements = [node for node in ast.walk(tree) if isinstance(node, ast.stmt)]
    scopes = [node for node in statements if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef))]
    symbols = [{'name': node.name, 'line': node.lineno} for node in scopes]
    lines = []
    for number, text in enumerate(source.splitlines(), 1):
        stripped = text.strip()
        if not stripped:
            note = 'Blank line; separates ideas without changing execution.'
        elif stripped.startswith('#'):
            note = 'Comment only; Python does not execute this line. ' + stripped.lstrip('# ').strip()
        elif stripped.startswith('@'):
            note = 'Decorator applied to the following function/class (for example dataclass, fixture, parametrization or route registration): ' + stripped[1:]
        elif stripped in ('else:', 'finally:') or stripped.startswith('except '):
            note = {'else:': 'Alternative branch; for try/except, this runs only when the try body succeeds.',
                    'finally:': 'Cleanup branch runs whether the preceding operations succeed or raise.'}.get(stripped, 'Handle only the listed exception types; unrelated exceptions still propagate.')
        else:
            candidates = [node for node in statements if node.lineno <= number <= node.end_lineno]
            node = min(candidates, key=lambda item: (item.end_lineno - item.lineno, -item.col_offset)) if candidates else None
            note = explain(node) if node else 'Continuation of Python syntax shown in the neighboring lines.'
            if node is not None and number != node.lineno:
                note = f'Continues the statement beginning at line {node.lineno}. ' + note
            extra = special_note(text)
            if extra:
                note += ' ' + extra
        lines.append((number, text, note))
    return lines, sorted(symbols, key=lambda item: item['line'])


def config_annotation(path: Path, line: str) -> str:
    value = line.strip()
    if not value:
        return 'Blank separator.'
    if value.startswith('#'):
        return 'Comment; not an executed directive.'
    if path.name == 'Makefile':
        if line.startswith('\t'):
            return 'Shell recipe run by make for the preceding target. $(BIN) resolves to .venv/bin; $(PYTHON) selects the setup interpreter.'
        if ':' in value and ':=' not in value:
            return 'Make target/dependency declaration. Invoke the target with make NAME.'
        return 'Make variable declaration; ?= supplies a default, := expands the value immediately.'
    if path.name == 'Dockerfile':
        return 'Container build/runtime directive. FROM chooses the base; RUN executes at build time; COPY adds local files; CMD supplies the default runtime command. Backslash continues a directive.'
    if path.suffix == '.toml':
        if value.startswith('['):
            return 'TOML section or list delimiter; groups package/build/test configuration.'
        return 'Package configuration or dependency constraint. dev, pqc and plots are optional extras installed explicitly.'
    if path.suffix == '.json':
        return 'JSON experiment configuration. This original file documents a matrix; the existing suite does not automatically read it. The policy run records its own exact config in metadata.json.'
    if path.suffix in ('.yml', '.yaml'):
        return 'YAML Compose setting. Indentation defines the service hierarchy; the current service runs the small smoke demo.'
    return 'Git ignore pattern. Matching untracked runtime/build files are omitted from normal status/add; already tracked files are unaffected.'


def main() -> None:
    paths = sorted((ROOT / 'src').rglob('*.py')) + sorted((ROOT / 'tests').rglob('*.py'))
    paths += sorted((ROOT / 'docs/architecture').glob('*.py'))
    paths += [ROOT / name for name in ('Makefile', 'pyproject.toml', 'Dockerfile', 'docker-compose.yml', 'configs/experiments.json', '.gitignore')]
    OUT.mkdir(parents=True, exist_ok=True)
    sections, nav, manifest = [], [], []
    total = 0
    for path in paths:
        rel = str(path.relative_to(ROOT))
        anchor = re.sub(r'[^a-zA-Z0-9_-]', '-', rel)
        if path.suffix == '.py':
            rows, symbols = annotations(path)
        else:
            rows = [(i, line, config_annotation(path, line)) for i, line in enumerate(path.read_text().splitlines(), 1)]
            symbols = []
        key = rel.removeprefix('src/qkd_hake/')
        overview = MODULES.get(key)
        if overview is None:
            overview = ('Pytest regression scenarios: read assertions as the exact claims under test. Fixtures and parametrization determine setup and case count.' if rel.startswith('tests/') else
                        'Package marker and module-level documentation.' if path.name == '__init__.py' else
                        'Build/runtime configuration; this does not itself implement the cryptographic protocol.')
        nav.append(f'<a href="#{anchor}">{escape(rel)}</a>')
        symbol_nav = ' · '.join(f'<a href="#{anchor}-L{sym["line"]}">{escape(sym["name"])}</a>' for sym in symbols)
        table_rows = []
        for number, source, note in rows:
            table_rows.append(f'<tr id="{anchor}-L{number}"><td class="ln"><a href="#{anchor}-L{number}">{number}</a></td><td class="code"><pre>{escape(source) or " "}</pre></td><td class="note">{escape(note)}</td></tr>')
        sections.append(f'<section id="{anchor}" data-name="{escape(rel)}"><h2>{escape(rel)}</h2><p class="overview">{escape(overview)}</p><p class="symbols">{symbol_nav}</p><table><thead><tr><th>Line</th><th>Exact source</th><th>Explanation</th></tr></thead><tbody>{"".join(table_rows)}</tbody></table></section>')
        manifest.append({'path': rel, 'lines': len(rows), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        total += len(rows)
    header = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>QKD–PQC annotated source</title>
<style>*{box-sizing:border-box}body{margin:0;color:#233642;background:#fff;font:15px/1.6 system-ui}aside{position:fixed;inset:0 auto 0 0;width:285px;padding:22px;background:#eef3f5;overflow:auto}aside a{display:block;font-size:12px;padding:4px 0;overflow-wrap:anywhere;color:#175b82}main{margin-left:285px;padding:35px;max-width:1800px}h1{font-size:32px}h2{font-size:21px;overflow-wrap:anywhere}section{margin:55px 0;scroll-margin-top:20px}a{color:#175b82}.overview{padding:15px;border-left:4px solid #237d70;background:#f1f8f6}.symbols{font-size:12px;line-height:2}table{width:100%;border-collapse:collapse;table-layout:fixed}th{text-align:left;background:#eaf0f3;padding:8px}th:first-child{width:55px}th:nth-child(2){width:52%}td{vertical-align:top;border-bottom:1px solid #e2e8ec;padding:5px 9px}.ln{color:#607888;font-size:11px}.code{background:#fafcfd}pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4;font:12px/1.6 ui-monospace,monospace}.note{font-size:13px;overflow-wrap:anywhere}tr:target{background:#fff0be}input{width:100%;padding:8px;margin:12px 0}button{padding:6px 10px}small{color:#607080}@media(max-width:900px){aside{position:relative;width:auto;max-height:250px}main{margin:0;padding:15px}th:nth-child(2){width:45%}}@media print{aside{display:none}main{margin:0;padding:0}section{break-before:page}thead{display:table-header-group}}</style></head><body><aside><b>Annotated source</b><input id="filter" placeholder="Filter by filename" aria-label="Filter by filename"><button id="reset">Show all files</button><nav>'''
    header += ''.join(nav) + '</nav></aside><main><h1>Every line, with its context</h1>'
    header += f'<p>{len(paths)} files · {total:,} source lines · snapshot generated from the current workspace.</p>'
    header += '<p>Read <a href="../../docs/SEMINAR_GUIDE.md">the seminar guide</a> for the complete concepts, message equations, commands, results and caveats. This companion combines curated module/security notes with syntax-aware statement explanations. Multiline statements are explained as a unit; each continuation points to its starting line. Comments describe author intent and can be stale. No runtime identities or secret files were read.</p><p>Use the filename filter or your browser’s Find command. Each line number has a direct anchor. Cryptographic names refer to symbolic values in source, never measured secret values. <a href="policy-comparison/report.html">Open the policy comparison</a>.</p>'
    footer = '''</main><script>const input=document.getElementById('filter');function filter(){const q=input.value.toLowerCase();document.querySelectorAll('section').forEach(s=>s.hidden=!s.dataset.name.toLowerCase().includes(q));document.querySelectorAll('nav a').forEach(a=>a.hidden=!a.textContent.toLowerCase().includes(q));}input.addEventListener('input',filter);document.getElementById('reset').onclick=()=>{input.value='';filter();};</script></body></html>'''
    (OUT / 'annotated-source.html').write_text(header + ''.join(sections) + footer)
    (OUT / 'annotation-manifest.json').write_text(json.dumps({'files': manifest, 'total_lines': total}, indent=2) + '\n')
    print(f'Annotated {total} lines across {len(paths)} files: {OUT / "annotated-source.html"}')


if __name__ == '__main__':
    main()
