from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import NamedTuple
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.crypto.kdf import rokdf, hmac_sha256_tag, serialize_fields
from qkd_hake.mitigations.mitigations import MitigationManager, AdmissionControlError, QuotaExceededError


class HandshakeError(Exception):
    pass


class QKDUnavailableError(HandshakeError):
    """A resource-policy failure that may be retried with a fresh handshake."""

    def __init__(self, message: str, reason_code: str = "qkd_client_unavailable") -> None:
        super().__init__(message)
        self.reason_code = reason_code


def validate_qkd_key(key: bytes | None, key_id: str) -> None:
    if not isinstance(key, bytes) or len(key) != 32 or not isinstance(key_id, str) or not key_id:
        raise HandshakeError("QKD delivery must contain a 256-bit key and a nonempty key ID")


class HandshakeResult(NamedTuple):
    session_key: bytes
    security_mode: str  # "HYBRID_QKD" or "SECURITY_LEVEL_DEGRADED_PQC_ONLY" or "PQC_ONLY"
    transcript: bytes


class AliceSession:
    def __init__(
        self,
        id_a: str,
        pk_a: bytes,
        sk_a: bytes,
        id_b: str,
        pk_b: bytes,
        algorithm: str = "ML-KEM-512",
        mitigation_mgr: MitigationManager | None = None,
        version: str = "1.0",
    ) -> None:
        self.id_a = id_a
        self.pk_a = pk_a
        self.sk_a = sk_a
        self.id_b = id_b
        self.pk_b = pk_b
        self.algorithm = algorithm
        self.mitigation_mgr = mitigation_mgr or MitigationManager()
        self.kem = OQSKEM(algorithm)
        self.version = version

        # Generate fresh nonce for anti-replay protection
        self.nonce_a = secrets.token_bytes(16)
        
        self.k1: bytes | None = None
        self.ct1: bytes | None = None

    def message1(self) -> tuple[bytes, bytes]:
        """Message 1: Alice encapsulates Bob's public key and sends (ct1, nonce_a)."""
        self.ct1, self.k1 = self.kem.encapsulate(self.pk_b)
        return self.ct1, self.nonce_a

    def message3(
        self,
        msg2_data: tuple[bytes, bytes, bytes, bytes],
        qkd_pool_client_fn=None,  # Function to fetch (k_qkd, qkdKeyId)
        allow_explicit_fallback: bool = True,
    ) -> tuple[bytes, str, bytes]:
        """
        Message 3: Alice verifies Bob's Message 2, decapsulates, encapsulates Bob's ephemeral key,
        fetches QKD key, and generates Message 3 tag.
        """
        pk_e, tau1, ct2, nonce_b = msg2_data
        self.nonce_b = nonce_b
        self.pk_e = pk_e
        self.ct2 = ct2

        # Transcript s binds ciphertexts for integrity
        s = self.ct1 + ct2

        # Verify tau1 using k1. Binds ephemeral key pk_e, nonce_b, and identity.
        expected_tau1 = hmac_sha256_tag(self.k1, pk_e + nonce_b + s + b"A")
        if not hmac.compare_digest(tau1, expected_tau1):
            raise HandshakeError("Alice failed to verify Bob's Message 2 MAC (tau1)")

        # Decapsulate k2
        k2 = self.kem.decapsulate(self.sk_a, ct2)

        # Encapsulate pk_e
        ct_star, k_star = self.kem.encapsulate(pk_e)

        # Fetch QKD key if not in pure PQC baseline mode
        k_qkd: bytes | None = None
        qkd_key_id: str = ""
        security_mode = "HYBRID_QKD"
        self.decision_reason = "qkd_available"

        # Apply quota check
        try:
            self.mitigation_mgr.check_quota(self.id_a)
        except QuotaExceededError as e:
            self.decision_reason = "request_quota_exceeded"
            if allow_explicit_fallback:
                k_qkd = None
                qkd_key_id = ""
                security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
            else:
                raise QKDUnavailableError(self.decision_reason, self.decision_reason) from e

        if security_mode == "HYBRID_QKD":
            if qkd_pool_client_fn is not None:
                try:
                    # Get current pool status to check admission control
                    status = qkd_pool_client_fn("status")
                    self.mitigation_mgr.check_admission_control(
                        status["stored_key_count"], status["max_key_count"]
                    )
                    
                    # Fetch key
                    k_qkd, qkd_key_id = qkd_pool_client_fn("get")
                except Exception as e:
                    self.decision_reason = (
                        "reserve_below_5_percent" if isinstance(e, AdmissionControlError)
                        else "qkd_acquisition_unavailable"
                    )
                    if allow_explicit_fallback:
                        k_qkd = None
                        qkd_key_id = ""
                        security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
                    else:
                        # Preserve the existing admission diagnostic, without exposing callback data.
                        reason = str(e) if isinstance(e, AdmissionControlError) else self.decision_reason
                        raise QKDUnavailableError(reason, self.decision_reason) from e
                else:
                    # Invalid delivered material is an error, never an implicit downgrade.
                    validate_qkd_key(k_qkd, qkd_key_id)
            else:
                self.decision_reason = "qkd_client_unavailable"
                if allow_explicit_fallback:
                    k_qkd = None
                    qkd_key_id = ""
                    security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
                else:
                    raise QKDUnavailableError("QKD is required but no key pool client is available")

        # Compute tau2 tag using k2
        tau2 = hmac_sha256_tag(k2, qkd_key_id.encode("utf-8") + ct_star + s + b"B")

        # Save state for session key derivation
        self.k2 = k2
        self.k_star = k_star
        self.ct_star = ct_star
        self.k_qkd = k_qkd
        self.qkd_key_id = qkd_key_id
        self.security_mode = security_mode
        self.tau1 = tau1
        self.tau2 = tau2

        return ct_star, qkd_key_id, tau2

    def derive_and_verify(self, tau3: bytes) -> HandshakeResult:
        """Derive final keys and verify Bob's confirmation tag tau3."""
        # Create canonical transcript containing required values
        raw_transcript = serialize_fields(
            self.version,
            self.id_a,
            self.id_b,
            self.algorithm,
            self.nonce_a,
            self.nonce_b,
            self.pk_a,
            self.pk_b,
            self.pk_e,
            self.ct1,
            self.ct2,
            self.ct_star,
            self.qkd_key_id,
            self.security_mode,
        )
        
        # Hashing using SHA3-256
        transcript_hash = hashlib.sha3_256(raw_transcript).digest()

        # Multi-input KDF inputs including transcript hash to bind security mode and identities
        c_kem = serialize_fields(
            self.id_a, self.pk_a, self.id_b, self.pk_b, self.pk_e, self.k1, self.k2, self.k_star, transcript_hash
        )
        c_qkd = serialize_fields(self.id_a, self.id_b, self.qkd_key_id, transcript_hash)

        sigma_qkd = self.k_qkd if self.k_qkd is not None else b""

        k_h = rokdf(self.k_star, c_kem, sigma_qkd, c_qkd)
        k1h = k_h[:32]
        k2h = k_h[32:]

        # Verify tau3 confirmation tag
        expected_tau3 = hmac_sha256_tag(
            k1h,
            serialize_fields(
                self.k1, self.qkd_key_id, self.pk_e, self.tau1, self.k2, self.tau2, transcript_hash
            ),
        )
        if not hmac.compare_digest(tau3, expected_tau3):
            raise HandshakeError("Alice failed to verify Bob's confirmation tag (tau3)")

        complete_transcript = raw_transcript + tau3

        return HandshakeResult(k2h, self.security_mode, complete_transcript)


class BobSession:
    def __init__(
        self,
        id_a: str,
        pk_a: bytes,
        id_b: str,
        pk_b: bytes,
        sk_b: bytes,
        algorithm: str = "ML-KEM-512",
        mitigation_mgr: MitigationManager | None = None,
        version: str = "1.0",
    ) -> None:
        self.id_a = id_a
        self.pk_a = pk_a
        self.id_b = id_b
        self.pk_b = pk_b
        self.sk_b = sk_b
        self.algorithm = algorithm
        self.mitigation_mgr = mitigation_mgr or MitigationManager()
        self.kem = OQSKEM(algorithm)
        self.version = version

        # Generate fresh nonce for anti-replay protection
        self.nonce_b = secrets.token_bytes(16)

    def message2(self, ct1_data: tuple[bytes, bytes]) -> tuple[bytes, bytes, bytes, bytes]:
        """Message 2: Bob receives (ct1, nonce_a), generates ephemeral keypair, decapsulates k1, encapsulates k2."""
        self.ct1, self.nonce_a = ct1_data
        
        # Ephemeral KEM
        self.kp_e = self.kem.generate_keypair()
        
        # Decapsulate k1
        self.k1 = self.kem.decapsulate(self.sk_b, self.ct1)
        
        # Encapsulate Alice's static key
        self.ct2, self.k2 = self.kem.encapsulate(self.pk_a)
        
        s = self.ct1 + self.ct2
        
        # Tag tau1 using k1. Binds nonce_b.
        self.tau1 = hmac_sha256_tag(self.k1, self.kp_e.public_key + self.nonce_b + s + b"A")
        
        return self.kp_e.public_key, self.tau1, self.ct2, self.nonce_b

    def message4(
        self,
        msg3_data: tuple[bytes, str, bytes],
        qkd_pool_client_fn=None,  # Function to retrieve key by ID
    ) -> tuple[bytes, HandshakeResult]:
        """Message 4: Bob receives Message 3, verifies tag, decapsulates ephemeral key, fetches QKD key."""
        ct_star, qkd_key_id, tau2 = msg3_data
        s = self.ct1 + self.ct2

        # Verify tau2 using k2
        expected_tau2 = hmac_sha256_tag(self.k2, qkd_key_id.encode("utf-8") + ct_star + s + b"B")
        if not hmac.compare_digest(tau2, expected_tau2):
            raise HandshakeError("Bob failed to verify Alice's Message 3 MAC (tau2)")

        # Decapsulate k*
        k_star = self.kem.decapsulate(self.kp_e.secret_key, ct_star)

        # Retrieve QKD key
        k_qkd: bytes | None = None
        security_mode = "HYBRID_QKD"
        if qkd_key_id:
            if qkd_pool_client_fn is not None:
                try:
                    k_qkd = qkd_pool_client_fn(qkd_key_id)
                except Exception as exc:
                    raise HandshakeError("Bob could not retrieve the QKD key") from exc
            else:
                raise HandshakeError("QKD key ID received without a retrieval client")
            validate_qkd_key(k_qkd, qkd_key_id)
        else:
            k_qkd = None
            security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"

        # Create canonical transcript
        raw_transcript = serialize_fields(
            self.version,
            self.id_a,
            self.id_b,
            self.algorithm,
            self.nonce_a,
            self.nonce_b,
            self.pk_a,
            self.pk_b,
            self.kp_e.public_key,
            self.ct1,
            self.ct2,
            ct_star,
            qkd_key_id,
            security_mode,
        )
        
        # Hashing using SHA3-256
        transcript_hash = hashlib.sha3_256(raw_transcript).digest()

        # Multi-input KDF including transcript hash
        c_kem = serialize_fields(
            self.id_a, self.pk_a, self.id_b, self.pk_b, self.kp_e.public_key, self.k1, self.k2, k_star, transcript_hash
        )
        c_qkd = serialize_fields(self.id_a, self.id_b, qkd_key_id, transcript_hash)

        sigma_qkd = k_qkd if k_qkd is not None else b""

        k_h = rokdf(k_star, c_kem, sigma_qkd, c_qkd)
        k1h = k_h[:32]
        k2h = k_h[32:]

        # Compute tau3 confirmation tag
        tau3 = hmac_sha256_tag(
            k1h,
            serialize_fields(
                self.k1, qkd_key_id, self.kp_e.public_key, self.tau1, self.k2, tau2, transcript_hash
            ),
        )

        complete_transcript = raw_transcript + tau3

        return tau3, HandshakeResult(k2h, security_mode, complete_transcript)
