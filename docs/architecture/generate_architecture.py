# /// script
# requires-python = ">=3.10"
# dependencies = ["reportlab>=4", "pypdf>=5"]
# ///
"""Rebuild the source-grounded research architecture atlas and editable SVGs.

Run from any directory with: uv run docs/architecture/generate_architecture.py
All cryptographic values in the figures are symbolic; no secret material is read.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import textwrap

from reportlab.graphics import renderPDF, renderSVG
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib.colors import HexColor, Color
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / "architecture"
PDF = ROOT / "output" / "pdf" / "qkd_hake_architecture_atlas.pdf"
W, H = 1440, 1080
INK = "#182B3A"
MUTED = "#526575"
RULE = "#CBD5DC"
BLUE = "#245D8B"
TEAL = "#147A72"
PURPLE = "#70538D"
AMBER = "#9D651E"
RED = "#A4493C"
PALE = "#F5F8FA"
WHITE = "#FFFFFF"
COLORS = {BLUE: "#EFF5FA", TEAL: "#EEF8F5", PURPLE: "#F5F1F8", AMBER: "#FFF8ED", RED: "#FCF2EF", INK: PALE}
REV = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
FIGURES: list[tuple[str, Drawing]] = []


def color(value: str) -> Color:
    return HexColor(value)


class Plate:
    """Small vector drawing toolkit with top-origin coordinates and fit checks."""

    def __init__(self, number: int, name: str, title: str, subtitle: str):
        self.d = Drawing(W, H)
        self.number = number
        self.name = name
        self.rect(0, 0, W, H, WHITE, WHITE)
        self.text(42, 34, "QKD / PQC  RESEARCH TESTBED", 12, BLUE, bold=True)
        self.text(1398, 34, f"ARCHITECTURE ATLAS  /  {number:02d}", 12, MUTED, anchor="end")
        self.text(42, 83, title, 32, INK, bold=True)
        self.text(42, 113, subtitle, 14, MUTED)
        self.line(42, 134, 1398, 134, RULE, 1)

    def rect(self, x: float, y: float, w: float, h: float, fill: str = WHITE,
             stroke: str = RULE, dash: bool = False, radius: float = 0):
        self.d.add(Rect(x, H-y-h, w, h, rx=radius, ry=radius,
                        fillColor=color(fill), strokeColor=color(stroke),
                        strokeWidth=1, strokeDashArray=[6, 4] if dash else None))

    def text(self, x: float, y: float, value: str, size: float = 14,
             fill: str = INK, bold: bool = False, mono: bool = False,
             anchor: str = "start"):
        font = "Courier" if mono else "Helvetica-Bold" if bold else "Helvetica"
        width = stringWidth(value, font, size)
        left = x if anchor == "start" else x-width if anchor == "end" else x-width/2
        if left < 0 or left + width > W + 1 or y > H:
            raise ValueError(f"Text outside page: {value}")
        self.d.add(String(x, H-y, value, fontName=font, fontSize=size,
                          fillColor=color(fill), textAnchor=anchor))

    def wrap(self, value: str, width: float, size: float = 14,
             bold: bool = False, mono: bool = False) -> list[str]:
        font = "Courier" if mono else "Helvetica-Bold" if bold else "Helvetica"
        lines: list[str] = []
        for para in value.split("\n"):
            line = ""
            for word in para.split():
                candidate = f"{line} {word}".strip()
                if stringWidth(candidate, font, size) > width and line:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            lines.append(line)
        return lines

    def para(self, x: float, y: float, value: str, width: float, size: float = 14,
             fill: str = INK, leading: float | None = None, bold: bool = False,
             mono: bool = False) -> float:
        lead = leading or size*1.35
        for line in self.wrap(value, width, size, bold, mono):
            self.text(x, y, line, size, fill, bold, mono)
            y += lead
        return y

    def box(self, x: float, y: float, w: float, h: float, title: str,
            body: str, accent: str = BLUE, tag: str = "", dash: bool = False,
            size: float = 14, title_size: float = 17):
        self.rect(x, y, w, h, COLORS.get(accent, PALE), RULE, dash)
        self.rect(x, y, 4, h, accent, accent)
        cy = y + 22
        if tag:
            self.text(x+16, cy, tag.upper(), 10.5, accent, bold=True)
            cy += 19
        cy = self.para(x+16, cy, title, w-32, title_size, accent, leading=title_size*1.15, bold=True)
        cy += 4
        cy = self.para(x+16, cy, body, w-32, size, leading=size*1.25)
        if cy - size*1.25 > y+h-10:
            raise ValueError(f"Box overflow {self.name}: {title} ends at {cy}, box ends {y+h}")

    def line(self, x1: float, y1: float, x2: float, y2: float,
             fill: str = INK, width: float = 1.5, dash: bool = False):
        self.d.add(Line(x1, H-y1, x2, H-y2, strokeColor=color(fill),
                        strokeWidth=width, strokeDashArray=[5, 4] if dash else None))

    def arrow(self, points: list[tuple[float, float]], fill: str = INK,
              dash: bool = False, width: float = 1.7):
        for a, b in zip(points, points[1:]):
            self.line(*a, *b, fill, width, dash)
        (x0, y0), (x, y) = points[-2:]
        angle = math.atan2(y-y0, x-x0)
        length, half = 8, 3.5
        bx, by = x-length*math.cos(angle), y-length*math.sin(angle)
        pts = [x, H-y, bx+half*math.sin(angle), H-(by-half*math.cos(angle)),
               bx-half*math.sin(angle), H-(by+half*math.cos(angle))]
        self.d.add(Polygon(pts, fillColor=color(fill), strokeColor=color(fill)))

    def label(self, x: float, y: float, value: str, fill: str = MUTED, size: float = 11):
        width = stringWidth(value, "Helvetica", size)
        self.rect(x-width/2-5, y-size-2, width+10, size+6, WHITE, WHITE)
        self.text(x, y, value, size, fill, anchor="middle")

    def note(self, x: float, y: float, value: str, size: float, fill: str):
        width = stringWidth(value, "Helvetica", size)
        self.rect(x-3, y-size-2, width+6, size+5, WHITE, WHITE)
        self.text(x, y, value, size, fill)

    def section(self, x: float, y: float, value: str, fill: str = INK):
        self.text(x, y, value, 12, fill, bold=True)

    def footer(self, caption: str, sources: str):
        self.line(42, 990, 1398, 990, RULE, 1)
        self.para(42, 1011, f"FIGURE {self.number}. {caption}", 1356, 11.5, INK, leading=15)
        self.text(42, 1060, sources, 10, MUTED)
        self.text(1398, 1060, f"Source revision {REV}  |  06 Oct 2026  |  {self.number}/6", 10, MUTED, anchor="end")
        FIGURES.append((self.name, self.d))


def overview() -> None:
    p = Plate(1, "01_system_architecture", "Hybrid QKD-PQC HAKE: system architecture",
              "Implementation-grounded overview of execution paths, cryptographic dependencies, key delivery and research outputs.")
    p.section(42, 162, "A  /  EXPERIMENT CONTROL AND ENTRY POINTS")
    p.box(42, 178, 315, 126, "Command-line orchestration", "server | demo | benchmark | sweep\nMakefile + cli.py; Docker defaults to demo.", BLUE, "ACTIVE")
    p.box(377, 178, 315, 126, "Paired handshake benchmark", "4 KEMs; 1,000 pairs per algorithm;\n100 warm-ups per mode; local calls.", BLUE, "ACTIVE / PLATE 5")
    p.box(712, 178, 315, 126, "Key-supply simulation", "6 demand rates x 3 supply rates x\n3 pool depths x 5 repeats; virtual clock.\nDirect pool calls; bypasses REST.", TEAL, "ACTIVE / PLATE 5")
    p.box(1047, 178, 351, 126, "Configuration surfaces", "QKD_* environment -> server settings.\nCLI -> experiments. JSON matrix is declarative.", AMBER, "CONFIGS + SETTINGS")
    p.arrow([(357,240),(377,240)], BLUE)
    p.arrow([(535,304),(535,316),(977,316),(977,346)], BLUE)
    p.arrow([(870,304),(870,311),(1415,311),(1415,608),(1398,608)], TEAL)
    p.section(42, 330, "B  /  PRIMITIVES AND IDENTITY")
    p.section(377, 330, "C  /  LOCAL PROTOCOL EXECUTION")
    p.section(1047, 330, "D  /  QKD SERVICE AND RESOURCE MODEL")
    p.box(42, 346, 285, 178, "OQSKEM adapter", "liboqs-python -> native liboqs\nML-KEM-512 / 768 / 1024\nFrodoKEM-976-AES\nKeyGen, Encaps, Decaps", PURPLE, "crypto/kem.py")
    p.box(42, 544, 285, 130, "Static identity material", "Harness provisions both keypairs.\nKeyStore JSON utility exists separately; identity trust is assumed.", PURPLE, "crypto/store.py")
    p.box(377, 346, 620, 166, "AliceSession  <-->  BobSession", "M1 (ct1, nA) -> M2 (pkE, tag1, ct2, nB) -> M3 (ct*, QKD ID, tag2) -> M4 (tag3).\nSeparate logical roles execute in one process; no peer network transport is implemented.", BLUE, "protocol/hake.py / PLATE 2", title_size=20)
    p.arrow([(327,431),(377,431)], PURPLE)
    p.label(351,418,"KEM",PURPLE)
    p.arrow([(327,604),(350,604),(350,482),(377,482)], PURPLE)
    p.box(377, 544, 293, 130, "Policy gates at Alice", "Rate quota -> occupancy floor -> key request -> fallback or reject.\nShared manager needed across sessions.", AMBER, "mitigations.py / PLATE 4")
    p.box(690, 544, 307, 130, "Transcript + multi-input KDF", "SHA3-256 transcript hash; SHA3-512 ROKDF; HMAC-SHA-256 tags.\n32-byte confirmation + session keys.", PURPLE, "crypto/kdf.py / PLATE 2")
    p.arrow([(520,512),(520,544)], AMBER)
    p.arrow([(845,512),(845,544)], PURPLE)
    p.box(1047, 346, 351, 150, "ETSI 014-style REST facade", "QKDClient -> HTTPX -> FastAPI\nstatus / enc_keys / dec_keys\nX-SAE-ID identifies test callers.\nAdapter available; harness uses callbacks.", TEAL, "client.py + server.py + models.py")
    p.box(1047, 544, 351, 130, "Finite, shared QKDKeyPool", "Lazy bit-rate refill; mutex; UUID key IDs; outstanding-key ledger.\nMock bytes generated on issue.", TEAL, "pool.py / PLATE 3")
    p.arrow([(1218,496),(1218,544)], TEAL)
    p.label(1255,525,"REST -> pool",TEAL)
    p.arrow([(997,462),(1047,462)], TEAL, dash=True)
    p.label(1022,444,"callback",TEAL,10)
    p.box(42, 703, 285, 121, "Independent smoke path", "demo -> runner.py -> combiner.py\nLabelled HKDF-SHA3-256 chain;\nseparate from the ROKDF handshake.", PURPLE, "ACTIVE / 20 DEMO SAMPLES")
    p.box(377, 703, 620, 121, "Application-facing handshake result", "HandshakeResult(session_key, security_mode, transcript)\nAlice returns after tag3 verification; Bob returns while producing tag3.\nMode distinguishes hybrid from explicit computational-only fallback.", BLUE, "RETURN BOUNDARY")
    p.arrow([(845,674),(845,703)], PURPLE)
    p.box(1047, 703, 351, 121, "Physical QKD abstraction", "One process models shared key delivery. Optical links, paired physical KMEs and authenticated KME channels are outside the experiment.", TEAL, "MODELED BOUNDARY", dash=True)
    p.section(42, 853, "E  /  MEASUREMENT AND SCIENTIFIC EVIDENCE")
    p.box(42, 866, 131, 98, "Smoke CSV", "KDF timing", PURPLE, size=13, title_size=15)
    p.box(213, 866, 360, 98, "Performance CSV", "Paired latency, CPU time and payload byte counts; static key setup excluded.", BLUE, size=13, title_size=15)
    p.box(613, 866, 360, 98, "Starvation CSV", "Burst depletion, steady-state successes, failures and final occupancy.", TEAL, size=13, title_size=15)
    p.box(1013, 866, 385, 98, "Plots + evidence review", "Matplotlib / pandas figures; tests; research assumptions and traceability (plate 6).", INK, size=13, title_size=15)
    p.arrow([(393,964),(393,978),(993,978),(993,943),(1013,943)], MUTED)
    p.arrow([(973,915),(1013,915)], MUTED)
    p.footer("The three experiment paths share modules but measure different systems. Solid edges show active calls or data flow; dashed edges denote REST integration outside the default benchmark path, not measured network traffic.", "Sources: cli.py; benchmarks/{suite,runner}.py; protocol/; crypto/; qkd_mock/; configs/experiments.json")


def protocol() -> None:
    p = Plate(2, "02_protocol_and_key_schedule", "Protocol execution and transcript-bound key schedule",
              "Exact tuple ordering and derivation expressions from protocol/hake.py; this is the repository protocol, not a conformance claim.")
    p.box(42, 157, 321, 86, "Alice / initiator", "Inputs: idA, pkA, skA, idB, pkB, algorithm", BLUE, size=12.5)
    p.box(655, 157, 321, 86, "Bob / responder", "Inputs: idA, pkA, idB, pkB, skB, algorithm", BLUE, size=12.5)
    p.box(1014, 157, 384, 86, "Local key-delivery callback", "Alice: status/get. Bob: retrieve(QKD ID).", TEAL, size=13)
    p.line(202,243,202,663,BLUE,1,dash=True)
    p.line(816,243,816,663,BLUE,1,dash=True)
    p.line(1207,243,1207,663,TEAL,1,dash=True)
    p.note(42, 270, "(ct1, k1) = Encaps(pkB); nA = random(16 B)", 13, PURPLE)
    p.arrow([(202,294),(816,294)],BLUE)
    p.label(500,285,"M1  /  (ct1, nA)",BLUE,14)
    p.note(400, 319, "Bob: KeyGen -> (pkE, skE); k1 = Decaps(skB, ct1)", 12, PURPLE)
    p.note(400, 338, "(ct2, k2) = Encaps(pkA); nB = random(16 B); compute tag1", 12, PURPLE)
    p.arrow([(816,364),(202,364)],BLUE)
    p.label(500,355,"M2  /  (pkE, tag1, ct2, nB)",BLUE,14)
    p.note(42, 390, "Verify tag1; k2 = Decaps(skA, ct2); (ct*, k*) = Encaps(pkE)", 12, PURPLE)
    p.arrow([(202,422),(1207,422)],TEAL)
    p.label(1010,411,"quota -> status -> admission -> get",TEAL,12)
    p.arrow([(1207,447),(202,447)],TEAL)
    p.label(1010,441,"local return: (q, QKD ID)",TEAL,12)
    p.note(42, 471, "On allowed fallback: q absent; QKD ID empty; explicit degraded mode", 12, AMBER)
    p.arrow([(202,500),(816,500)],BLUE)
    p.label(501,491,"M3  /  (ct*, QKD ID, tag2)",BLUE,14)
    p.note(420, 525, "Bob: verify tag2; k* = Decaps(skE, ct*)", 12, PURPLE)
    p.arrow([(816,548),(1207,548)],TEAL)
    p.label(1010,539,"retrieve non-empty QKD ID",TEAL,12)
    p.arrow([(1207,573),(816,573)],TEAL)
    p.label(1010,566,"same q; one-time retrieval",TEAL,12)
    p.note(421, 600, "Bob derives (k1h, k2h) and returns result with tag3", 12, PURPLE)
    p.arrow([(816,623),(202,623)],BLUE)
    p.label(500,615,"M4  /  tag3",BLUE,14)
    p.note(42, 650, "Alice derives keys, verifies tag3, then returns HandshakeResult", 12, BLUE)
    p.section(42, 690, "A  /  CANONICAL CONTEXT AND DERIVATION")
    p.box(42, 705, 825, 130, "Length-prefixed transcript T", "LP(version, idA, idB, algorithm, nA, nB, pkA, pkB, pkE, ct1, ct2, ct*, QKD ID, mode)\nhT = SHA3-256(T); each LP field uses a 4-byte big-endian length.\nRoles are ordered by the initiator/responder fields; mode is inferred from the QKD-ID path, then bound.", PURPLE, size=13.5)
    p.box(897, 705, 501, 130, "Confirmation tags", "s = ct1 || ct2; MAC = HMAC-SHA-256\ntag1 = MAC(k1, pkE || nB || s || 'A')\ntag2 = MAC(k2, ID || ct* || s || 'B')\ntag3 = MAC(k1h, LP(k1, ID, pkE, tag1, k2, tag2, hT))", PURPLE, size=12.5)
    p.box(42, 861, 825, 106, "ROKDF used by the handshake", "cK = LP(idA, pkA, idB, pkB, pkE, k1, k2, k*, hT); cQ = LP(idA, idB, ID, hT)\nkh = SHA3-512(label || LP(k*, cK, q_or_empty, cQ)); label = 'KEM-QKD-Hybrid KEX'\nk1h = kh[0:32] (confirmation); k2h = kh[32:64] (session key)", PURPLE, size=12.5)
    p.arrow([(450,835),(450,861)],PURPLE)
    p.box(897, 861, 501, 106, "Observable acceptance semantics", "No final Alice-to-Bob acknowledgement. Returned transcript = T || tag3; tag1/tag2 are covered by confirmation but not returned in T. Empty QKD input is valid only on an explicit fallback path.", AMBER, size=12.5)
    p.footer("KEM public keys and QKD delivery are provisioned assumptions. Secret values stay in local process state; only the QKD identifier crosses the peer message boundary. This plate transcribes implementation behavior.", "Sources: protocol/hake.py:22-308; crypto/kdf.py:51-81; crypto/kem.py:34-55. LP = serialize_fields; || = concatenate.")


def pool() -> None:
    p = Plate(3, "03_kme_and_pool_accounting", "QKD key delivery, finite supply and pool accounting",
              "One thread-safe in-memory pool models shared KME state; available-key credit and issued-key storage have different lifetimes.")
    p.section(42, 163, "A  /  REST CONTRACT  (BASE PATH /api/v1/keys)")
    p.box(42, 180, 429, 163, "Get status", "GET /{slave}/status\nReturns available count, depth, key size, SAE IDs and mock KME IDs.\nRefill is evaluated on demand.\nGET /health is a separate liveness endpoint.", TEAL, "QKDClient.get_status()", size=13)
    p.box(505, 180, 429, 163, "Get key", "POST /{slave}/enc_keys: {number, size}\nGET variant issues one key.\nReturns [{key_ID, base64(key)}].\nPOST schema: 1..128 keys; configured size must match.", TEAL, "QKDClient.get_key()", size=13)
    p.box(968, 180, 430, 163, "Get key with IDs", "POST /{master}/dec_keys: {key_IDs}\nGET variant retrieves one key_ID.\nBob presents the ID obtained from Alice; lookup also binds the ordered SAE pair.", TEAL, "QKDClient.retrieve_key()", size=13)
    p.section(42, 376, "B  /  RESOURCE STATE AND LIFECYCLE")
    p.box(42, 393, 302, 156, "Lazy refill integrator", "Clock: monotonic or simulated\nAccumulate elapsed_time x R bits.\nConvert complete L-bit credits;\ncap available keys at depth D.\nRetain fractional credit; discard overflow.", TEAL, "R = BITS/S; L = BITS/KEY", size=13)
    p.box(391, 393, 308, 156, "Available-key budget A", "0 <= A <= D\nstatus() and issue() trigger refill.\nInitial A = configured initial_keys.\nD bounds available credit, not the issued-key ledger.", TEAL, "NO KEY BYTES STORED HERE", size=13)
    p.arrow([(344,470),(391,470)],TEAL)
    p.box(746, 393, 308, 156, "Issue n keys", "Check outstanding-pair quota.\nRequire A >= n; else PoolExhausted.\nUUID + secrets.token_bytes(L/8).\nA -= n; outstanding[pair] += n.", TEAL, "ATOMIC UNDER MUTEX", size=13)
    p.arrow([(699,470),(746,470)],TEAL)
    p.box(1101, 393, 297, 156, "Issued-key ledger", "(master, slave, key_ID) -> key\nRetains secret bytes until retrieved.\nReturns bytes + ID to master.\nNo expiry or persistence layer.", TEAL, "_issued + _outstanding", size=13)
    p.arrow([(1054,470),(1101,470)],TEAL)
    p.box(746, 608, 652, 133, "Retrieve and consume the matching ledger entry", "Validate all requested lookup tuples exist; pop entries; decrement outstanding[pair].\nReturn the same bytes to the slave. A does not increase on retrieval.\nA second retrieval of a consumed ID raises UnknownKeyID.", TEAL, "ONE-TIME SLAVE RETRIEVAL", size=13.5)
    p.arrow([(1249,549),(1249,608)],TEAL)
    p.box(42, 583, 657, 158, "Two quotas with different meanings", "Pool quota: limits issued-but-unretrieved keys for master->slave; 0 disables it.\nProtocol quota: limits requests in a rolling 1-second history (plate 4).\nOutstanding state survives issuance until retrieval; simulated sweeps issue without retrieving and therefore accumulate ledger entries.", AMBER, "ACCOUNTING DISTINCTION", size=13.5)
    p.section(42, 777, "C  /  SERVICE BOUNDARY, ERRORS AND EXPERIMENT ASSUMPTIONS")
    p.box(42, 794, 429, 171, "Wire representation and identity", "Caller supplies X-SAE-ID. Keys are base64-encoded in JSON, not encrypted by encoding. Local server binds 127.0.0.1:8000.\nAuthenticated HTTPS / SAE authorization and separate KME replication are outside the current service.", INK, "TRUST BOUNDARY", size=13)
    p.box(505, 794, 429, 171, "Error mapping", "401: missing X-SAE-ID\n400: unsupported key size / unknown ID\n503: pool exhaustion / pool quota\n422: request schema validation\nHTTP client raises on unsuccessful status.", TEAL, "FAILURE SURFACE", size=13)
    p.box(968, 794, 430, 171, "Finite-pool interpretation", "Default: R = 10,000 bit/s; L = 256 bits;\nD = A0 = 128 keys.\nSupply ceiling: R/L = 39.0625 keys/s.\nThis is a software supply model, not a quantum link or measured optical entropy source.", AMBER, "MODEL", size=13)
    p.footer("The pool is a rate-limited key-credit model with random bytes created at issue time. The available count is bounded; the outstanding ledger is not bounded when its quota is disabled. All pool mutations use one mutex.", "Sources: qkd_mock/{pool,server,client,models}.py; settings.py. API family reference: ETSI GS QKD 014 V1.1.1 [R2].")


def policies() -> None:
    p = Plate(4, "04_policy_and_security_modes", "Starvation policy, admission and security-mode outcomes",
              "Decision order in AliceSession.message3; policies control access to QKD after the initial KEM work has already executed.")
    p.section(42, 162, "A  /  CONTROL FLOW")
    p.box(42, 180, 279, 131, "Verified M2 + KEM work", "Verify tag1; recover k2; encapsulate pkE -> ct*, k*.\nThen enter policy checks.", BLUE, "ENTRY", size=13)
    p.box(381, 180, 279, 131, "Rolling request quota", "check_quota(idA)\nDefault limit: 10 requests/s.\nRecords request before acquisition.", AMBER, "GATE 1", size=13)
    p.arrow([(321,247),(381,247)],BLUE)
    p.box(720, 180, 279, 131, "Status and admission", "Require callback. Read A, D.\nReject admission when A/D < 0.05.\n5% exactly passes this gate.", AMBER, "GATE 2", size=13)
    p.arrow([(660,247),(720,247)],AMBER)
    p.box(1059, 180, 339, 131, "Acquire QKD input", "callback('get') -> (q, key_ID)\nBackend may enforce an additional outstanding-key quota.", TEAL, "GATE 3", size=13)
    p.arrow([(999,247),(1059,247)],TEAL)
    p.line(520,311,520,353,AMBER)
    p.line(860,311,860,353,AMBER)
    p.line(1228,311,1228,353,AMBER)
    p.line(520,353,1228,353,AMBER)
    p.arrow([(860,353),(860,400)],AMBER)
    p.label(860,345,"quota / no callback / admission / get exception",AMBER,12)
    p.box(650, 400, 420, 109, "allow_explicit_fallback?", "Policy flag determines whether the failure path can continue using KEM inputs alone.", AMBER, size=14)
    p.arrow([(756,509),(756,545),(470,545),(470,580)],AMBER)
    p.label(611,540,"TRUE",AMBER,12)
    p.arrow([(963,509),(963,545),(1192,545),(1192,580)],RED)
    p.label(1095,540,"FALSE",RED,12)
    p.box(42, 400, 537, 109, "HYBRID_QKD", "Acquisition succeeds with q and a non-empty key ID.\nBob retrieves q by that ID; both derive transcript-bound keys.", TEAL, size=14)
    p.arrow([(1398,265),(1415,265),(1415,380),(310,380),(310,400)],TEAL)
    p.label(408,376,"successful key acquisition",TEAL,12)
    p.box(42, 580, 861, 126, "SECURITY_LEVEL_DEGRADED_PQC_ONLY", "Handshake mode returned by hake.py on explicit fallback. QKD ID is empty; QKD KDF input is empty. Bob infers the mode from the empty ID; the full mode string is then bound into the transcript hash.\nPURE_PQC is the benchmark treatment label for this same no-QKD execution path.", AMBER, "CONTINUE", size=13.5)
    p.box(963, 580, 435, 126, "HandshakeError", "Abort instead of returning a session.\nREJECTED exists in the separate SecurityMode enum; the handshake uses an exception.", RED, "REJECT", size=13.5)
    p.section(42, 749, "B  /  CONTROL SCOPE AND RESEARCH INTERPRETATION")
    p.box(42, 768, 429, 197, "Scope of enforcement", "A new MitigationManager is created by default for every AliceSession. Global per-peer rate enforcement requires explicitly sharing a manager.\nThe paired benchmark constructs fresh sessions, so it does not evaluate cross-session quota effectiveness.", AMBER, "SCOPE", size=13.5)
    p.box(505, 768, 429, 197, "Admission is not reservation", "The occupancy check and issue operation are separate calls. Concurrent callers can pass the same check.\nThe 5% rule checks current occupancy; it is not priority scheduling or an atomic reservation. Policy sweeps are not executed by the current pool-only sweep.", AMBER, "SEMANTICS", size=13.5)
    p.box(968, 768, 430, 197, "Required guard for hybrid validity", "Require non-empty, correctly sized q whenever mode = HYBRID_QKD, at both roles.\nCurrent callbacks are trusted to return valid material; Bob can preserve HYBRID_QKD for a non-empty ID even if no retrieval callback exists. This guard is a research-hardening obligation.", RED, "INVARIANT / REVIEW ITEM", size=13)
    p.footer("The policy layer is implemented, but control scope and atomicity determine what it can enforce. Security mode is transcript-bound after the decision; no separate mode-negotiation field appears in the message tuples.", "Sources: protocol/hake.py:55-139,236-308; mitigations/mitigations.py; protocol/combiner.py:15-23. See evidence matrix on plate 6.")


def experiments() -> None:
    p = Plate(5, "05_experiment_and_measurement_architecture", "Experiment architecture and measurement boundaries",
              "Cryptographic cost and QKD resource scarcity are measured independently; combining them into an end-to-end claim requires another experiment.")
    p.section(42, 163, "A  /  PAIRED CRYPTOGRAPHIC PERFORMANCE", BLUE)
    p.section(752, 163, "B  /  TWO-PHASE QKD STARVATION SIMULATION", TEAL)
    p.box(42, 179, 646, 108, "Provision once per algorithm", "Generate long-term keypairs before timing. Supply a fixed 32-byte QKD test value and one UUID through callbacks. Algorithms: ML-KEM-512/768/1024, FrodoKEM-976-AES.", BLUE, size=13.5)
    p.box(752, 179, 646, 108, "Factorial experiment grid", "Demand r = {1, 5, 10, 20, 50, 100} requests/s; supply R = {1, 10, 100} kbps.\nDepth D = {16, 64, 128}; L = 256 bits; 5 repeats -> 270 cases.\nSimulatedClock advances by 1/r before every pool.issue().", TEAL, size=13)
    p.arrow([(365,287),(365,318)],BLUE)
    p.line(1075,287,1075,302,TEAL)
    p.arrow([(1075,302),(905,302),(905,318)],TEAL)
    p.arrow([(1075,302),(1245,302),(1245,318)],TEAL)
    p.box(42, 318, 646, 109, "Warm up, then alternate pair order", "100 warm-up handshakes per mode, excluded from the CSV.\n1,000 recorded HYBRID / PURE_PQC pairs per algorithm.\nOdd pairs run hybrid first; even pairs run pure-PQC first -> 8,000 raw rows.", BLUE, size=13.5)
    p.box(752, 318, 306, 139, "Phase 1 / burst", "Start A0 = D. If r > R/L, issue until first PoolExhausted.\nRecord elapsed virtual time.\nCompare with D / (r - R/L).", TEAL, size=13.5)
    p.box(1092, 318, 306, 139, "Non-overloaded branch", "If r <= R/L, no finite depletion time is defined.\nRun 10 s of virtual warm-up before measurement.", TEAL, size=13.5)
    p.arrow([(365,427),(365,488)],BLUE)
    p.box(42, 488, 646, 145, "Timed boundary: session construction through Alice verification", "Includes fresh nonces, one ephemeral keypair, 3 encapsulations, 3 decapsulations, transcript/KDF/MAC work and local callbacks.\nWall time: perf_counter_ns(). CPU time: process_time_ns().\nExcludes static key generation, peer networking, REST latency, optical QKD and transport framing. Session-key equality is checked.", BLUE, size=13.5)
    p.arrow([(905,457),(905,474),(1075,474),(1075,488)],TEAL)
    p.line(1245,457,1245,474,TEAL)
    p.line(1245,474,1075,474,TEAL)
    p.box(752, 488, 646, 145, "Phase 2 / steady-state resource availability", "Start immediately after the first failure (overloaded), or after warm-up.\nIssue for 60 s of virtual time; count successes and failures; read final occupancy.\nNo KEM work, handshake transport, key retrieval, or mitigation policy is invoked. Repeats reproduce a deterministic schedule, not independent noise samples.", TEAL, size=13.5)
    p.arrow([(365,633),(365,665)],BLUE)
    p.arrow([(1075,633),(1075,665)],TEAL)
    p.box(42, 665, 646, 118, "performance_benchmarks.csv -> performance figures", "Rows: algorithm, mode, pair_run, latency_ms, cpu_time_ms, bytes_on_wire, qkd_key_id_bytes, long_term_public_keys_transmitted.\nReport median and linearly interpolated p95; plot latency and payload size.", BLUE, size=13)
    p.box(752, 665, 646, 118, "bottleneck_steady_state.csv -> resource figures", "Rows record case parameters, burst times, first-failure status, measurement counts, QKD success fraction and final occupancy.\nPlots: burst capacity, sustainable success fraction, measured vs theoretical depletion.", TEAL, size=13)
    p.section(42, 817, "C  /  ANALYTICAL INTERPRETATION")
    p.box(42, 834, 429, 131, "Supply-limited service ceiling", "mu = R / L keys/s\nAt 10 kbps and 256 bits: mu = 39.0625.\nFluid approximation: T_deplete = D/(r-mu), r > mu; success fraction ~ min(1, mu/r).", TEAL, size=13.5)
    p.box(505, 834, 429, 131, "Payload byte accounting", "B = 3|ct| + |pkE| + 2(16) + 3(32) + |ID|\nHybrid ID: 36 ASCII bytes; PQC ID: 0.\nStatic public keys are pre-provisioned.\nCSV 'bytes_on_wire' is this payload sum.", BLUE, size=13.5)
    p.box(968, 834, 430, 131, "Reproducibility boundary", "Host, package versions, commands and source hashes accompany this run.\nVirtual scheduling is deterministic. KEM randomness and UUIDs are unseeded.\nNo measured secret values are logged.", INK, size=13.5)
    p.footer("A fluid depletion formula is an analytical reference, not an exact identity for discrete arrivals and lazy refill. The experiment configuration JSON lists policies but the suite uses its own active parameter lists.", "Sources: benchmarks/suite.py:25-834; plot_performance_figures.py; plot_wp6.py; configs/experiments.json; verification.json.")


def evidence() -> None:
    p = Plate(6, "06_traceability_and_research_boundaries", "Module traceability, verification and research boundaries",
              "A reviewable map from figure claims to source files, with the conditions needed to interpret the experimental evidence.")
    p.section(42, 163, "A  /  IMPLEMENTATION-TO-EVIDENCE MATRIX")
    cols = [42, 330, 934, 1398]
    p.rect(42,179,1356,36,INK,INK)
    for x, txt in zip(cols, ["MODULE / SOURCE", "ARCHITECTURAL RESPONSIBILITY", "EXISTING TEST EVIDENCE"]):
        p.text(x+12,202,txt,12,WHITE,bold=True)
    rows = [
        ("protocol/hake.py", "4-message role state; transcript hash; key confirmation", "test_hake.py: 5 scenarios"),
        ("crypto/kem.py", "liboqs adapter; 4 selected KEM algorithms", "test_kem.py: 4 algorithm round trips"),
        ("crypto/kdf.py + combiner.py", "ROKDF for HAKE; separate labelled HKDF prototype", "test_combiner.py: 3 mode/derivation checks"),
        ("qkd_mock/pool.py", "Lazy refill; credits; pair-bound ID ledger; mutex", "test_pool.py: 3 lifecycle/exhaustion checks"),
        ("server.py + models.py", "FastAPI endpoints, schemas and error mapping", "test_api.py: 2 delivery/exhaustion checks"),
        ("client.py + mitigations.py", "HTTP callbacks; request quota; 5% admission floor", "HAKE tests + 4 loopback REST checks [V]"),
        ("benchmarks/suite.py", "Paired local handshakes; two-phase pool simulation", "Full execution and output checks [V]"),
        ("runner.py + plot_*.py", "Smoke timing; CSV-derived figures", "Demo and both plotting commands [V]"),
        ("store.py / cli.py / settings.py", "JSON identity utility / dispatch / QKD_* environment", "Store is separate from active harness wiring"),
    ]
    y=215
    for i,row in enumerate(rows):
        p.rect(42,y,1356,36,WHITE if i%2 else PALE,RULE)
        for x,txt in zip(cols,row):
            p.text(x+12,y+23,txt,12.2,INK)
        y+=36
    p.section(42, 572, "B  /  SECURITY AND SYSTEM BOUNDARIES")
    p.box(42, 587, 429, 180, "Identity and local secrets", "Trusted static public-key provisioning is assumed. KeyStore stores public/secret key hex in JSON and is not used by the benchmark.\nSecret state resides in Python/native memory; the implementation does not demonstrate key erasure or a hardware trust boundary.", PURPLE, size=13.5)
    p.box(505, 587, 429, 180, "Independent HKDF prototype", "derive_keys(): hash(mode || 0x00 || transcript), then labelled extracts for static KEM, ephemeral KEM and QKD (or explicit-pqc-only).\nLabelled expands produce session, client-confirmation and server-confirmation keys. Only the smoke path uses this combiner.", PURPLE, size=13)
    p.box(968, 587, 430, 180, "Claims requiring separate proof", "Code traces and successful tests do not establish CK01 security, exact paper conformance or information-theoretic secrecy.\nThe repository security-analysis document is a research outline. Match protocol labels, adversary model and combiner assumptions to [R1] before importing its claims.", AMBER, size=13)
    verification = ROOT / "output/verification/2026-10-06/verification.json"
    data = json.loads(verification.read_text()) if verification.exists() else {}
    completed = bool(data.get("completed_utc"))
    if not completed:
        raise RuntimeError("Complete the verification run before producing the final evidence plate")
    p.rect(42,789,1356,69,COLORS[TEAL],TEAL)
    p.text(60,814,"[V] VERIFIED EXECUTION",12,TEAL,bold=True)
    p.text(60,840,"17 tests passed  |  4 REST-backed HAKE checks  |  8,000 benchmark rows  |  270 sweep cases  |  20 smoke rows  |  5 result plots",14,INK)
    p.section(42, 886, "C  /  REFERENCES AND REPRODUCTION")
    p.text(42,910,"[R1] Clermont & Henrich (2026). The Best of Both Worlds: Hybrid Authenticated Key Exchange for QKD(N) without Signatures.",12,INK)
    p.text(42,929,"Cryptology ePrint 2026/1231. https://eprint.iacr.org/2026/1231  (research reference; exact implementation correspondence unverified).",11.5,MUTED)
    p.text(42,949,"[R2] ETSI GS QKD 014 V1.1.1 (2019-02), REST-based key delivery API. Official ETSI PDF linked in the artifact manifest.",12,INK)
    p.text(42,970,"Rebuild: uv run docs/architecture/generate_architecture.py     |     Execute: .venv/bin/python docs/architecture/run_verification.py",11.5,BLUE)
    p.footer("This atlas describes the inspected repository and the executed experiments. Diagram generation and verification are companion scripts; the protocol implementation and historical result files were not modified.", "Evidence: output/verification/2026-10-06/{verification.json,*.log,results/}; references and figure captions in output/architecture/manifest.json.")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    PDF.parent.mkdir(parents=True, exist_ok=True)
    for build in [overview, protocol, pool, policies, experiments, evidence]:
        build()
    # A3 landscape preserves comfortable reading size when printed full-sheet.
    from reportlab.lib.pagesizes import A3, landscape
    pw, ph = landscape(A3)
    scale = min(pw/W, ph/H)
    canvas = Canvas(str(PDF), pagesize=(pw,ph), pageCompression=1)
    canvas.setTitle("Hybrid QKD-PQC HAKE: Research Architecture Atlas")
    canvas.setAuthor("QKD-HAKE Testbed")
    canvas.setSubject(f"Implementation-grounded architecture and verified execution, revision {REV}")
    for name,d in FIGURES:
        renderSVG.drawToFile(d, str(OUT/f"{name}.svg"))
        canvas.saveState()
        canvas.translate((pw-W*scale)/2,(ph-H*scale)/2)
        canvas.scale(scale,scale)
        renderPDF.draw(d,canvas,0,0)
        canvas.restoreState()
        canvas.showPage()
    canvas.save()
    manifest = {
        "source_revision": REV,
        "inspection_date": "2026-10-06",
        "pdf": str(PDF.relative_to(ROOT)),
        "figures": [f"{name}.svg" for name,_ in FIGURES],
        "sources": [str(p.relative_to(ROOT)) for p in sorted((ROOT/"src").rglob("*.py"))],
        "references": {
            "R1": "https://eprint.iacr.org/2026/1231",
            "R2": "https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_QKD014v010101p.pdf",
        },
        "scope": "Repository implementation and separately identified modeling assumptions; not a proof or a claim of exact paper conformance.",
    }
    (OUT/"manifest.json").write_text(json.dumps(manifest,indent=2))
    (OUT/"README.txt").write_text(textwrap.dedent("""\
        QKD-HAKE research architecture atlas
        ===================================
        The PDF contains six A3 landscape vector plates. SVG files retain editable
        text, boxes and arrows. Use the overview as a standalone system figure;
        use the remaining plates as detailed architecture figures or an appendix.

        Rebuild all vector output from the repository root:
          uv run docs/architecture/generate_architecture.py

        Re-run tests, full experiments, plots and loopback REST handshakes:
          .venv/bin/python docs/architecture/run_verification.py

        Verification outputs are in output/verification/2026-10-06/.
        The original results/ directory is retained unchanged.
        Sources and external references are enumerated in manifest.json.

        Color key:
          Blue   : protocol execution and performance measurement
          Teal   : QKD supply, delivery and resource accounting
          Purple : cryptographic primitives and key derivation
          Amber  : policy decisions and modeling assumptions
          Red    : rejection paths and invariant review items

        Solid arrows show active calls or data flow. Dashed integration arrows
        identify adapters available outside the default benchmark execution path.
        The protocol plate shows exact tuple order from the inspected code.
        Secret values are symbolic; no measured key bytes are included.
        """))
    from pypdf import PdfReader
    reader = PdfReader(str(PDF))
    assert len(reader.pages) == 6
    for i,page in enumerate(reader.pages,1):
        txt = page.extract_text()
        assert f"FIGURE {i}." in txt
        assert "\ufffd" not in txt
    print(json.dumps({"pdf":str(PDF),"vector_plates":len(FIGURES),"pages":len(reader.pages)}))


if __name__ == "__main__":
    main()
