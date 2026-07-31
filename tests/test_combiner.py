import pytest

from qkd_hake.protocol.combiner import QKDRequired, SecurityMode, derive_keys


def test_hybrid_mode_when_qkd_key_exists() -> None:
    result = derive_keys(
        static_kem_secret=b"a" * 32,
        ephemeral_kem_secret=b"b" * 32,
        qkd_key=b"c" * 32,
        transcript=b"handshake transcript",
        allow_explicit_pqc_fallback=False,
    )
    assert result.mode is SecurityMode.HYBRID_QKD
    assert len(result.session_key) == 32


def test_qkd_starvation_rejects_when_fallback_is_disabled() -> None:
    with pytest.raises(QKDRequired):
        derive_keys(
            static_kem_secret=b"a" * 32,
            ephemeral_kem_secret=b"b" * 32,
            qkd_key=None,
            transcript=b"handshake transcript",
            allow_explicit_pqc_fallback=False,
        )


def test_explicit_fallback_changes_mode_and_key() -> None:
    common = {
        "static_kem_secret": b"a" * 32,
        "ephemeral_kem_secret": b"b" * 32,
        "transcript": b"handshake transcript",
    }
    hybrid = derive_keys(
        **common, qkd_key=b"c" * 32, allow_explicit_pqc_fallback=False
    )
    pqc = derive_keys(**common, qkd_key=None, allow_explicit_pqc_fallback=True)
    assert pqc.mode is SecurityMode.PQC_ONLY
    assert pqc.session_key != hybrid.session_key
