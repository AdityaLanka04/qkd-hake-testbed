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
