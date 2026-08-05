from __future__ import annotations

import hmac
import secrets
from typing import NamedTuple
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.crypto.kdf import rokdf, hmac_sha256_tag, serialize_fields
from qkd_hake.mitigations.mitigations import MitigationManager, AdmissionControlError, QuotaExceededError


class HandshakeError(Exception):
    pass


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
    ) -> None:
        self.id_a = id_a
        self.pk_a = pk_a
        self.sk_a = sk_a
        self.id_b = id_b
        self.pk_b = pk_b
        self.algorithm = algorithm
        self.mitigation_mgr = mitigation_mgr or MitigationManager()
        self.kem = OQSKEM(algorithm)

        self.k1: bytes | None = None
        self.ct1: bytes | None = None

    def message1(self) -> bytes:
        """Message 1: Alice encapsulates Bob's public key."""
        self.ct1, self.k1 = self.kem.encapsulate(self.pk_b)
        return self.ct1

    def message3(
        self,
        msg2_data: tuple[bytes, bytes, bytes],
        qkd_pool_client_fn=None,  # Function to fetch (k_qkd, qkdKeyId)
        allow_explicit_fallback: bool = True,
    ) -> tuple[bytes, str, bytes]:
        """
        Message 3: Alice verifies Bob's Message 2, decapsulates, encapsulates Bob's ephemeral key,
        fetches QKD key, and generates Message 3 tag.
        """
        pk_e, tau1, ct2 = msg2_data
        s = self.ct1 + ct2

        # Verify tau1 using k1
        expected_tau1 = hmac_sha256_tag(self.k1, pk_e + s + b"A")
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

        # Apply quota check
        try:
            self.mitigation_mgr.check_quota(self.id_a)
        except QuotaExceededError as e:
            if allow_explicit_fallback:
                k_qkd = None
                qkd_key_id = ""
                security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
            else:
                raise HandshakeError(str(e)) from e

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
                except (AdmissionControlError, Exception) as e:
                    if allow_explicit_fallback:
                        k_qkd = None
                        qkd_key_id = ""
                        security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
                    else:
                        raise HandshakeError(str(e)) from e
            else:
                if allow_explicit_fallback:
                    k_qkd = None
                    qkd_key_id = ""
                    security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
                else:
                    raise HandshakeError("QKD is required but no key pool client is available")


        # Compute tau2 tag using k2
        tau2 = hmac_sha256_tag(k2, qkd_key_id.encode("utf-8") + ct_star + s + b"B")

        # Save state for session key derivation
        self.pk_e = pk_e
        self.k2 = k2
        self.k_star = k_star
        self.ct_star = ct_star
        self.k_qkd = k_qkd
        self.qkd_key_id = qkd_key_id
        self.security_mode = security_mode
        self.ct2 = ct2
        self.tau1 = tau1
        self.tau2 = tau2

        return ct_star, qkd_key_id, tau2

    def derive_and_verify(self, tau3: bytes) -> HandshakeResult:
        """Derive final keys and verify Bob's confirmation tag tau3."""
        # Multi-input KDF inputs
        c_kem = serialize_fields(
            self.id_a, self.pk_a, self.id_b, self.pk_b, self.pk_e, self.k1, self.k2, self.k_star
        )
        c_qkd = serialize_fields(self.id_a, self.id_b, self.qkd_key_id)

        sigma_qkd = self.k_qkd if self.k_qkd is not None else b""

        k_h = rokdf(self.k_star, c_kem, sigma_qkd, c_qkd)
        k1h = k_h[:32]
        k2h = k_h[32:]

        # Verify tau3
        expected_tau3 = hmac_sha256_tag(
            k1h,
            serialize_fields(
                self.k1, self.qkd_key_id, self.pk_e, self.tau1, self.k2, self.tau2
            ),
        )
        if not hmac.compare_digest(tau3, expected_tau3):
            raise HandshakeError("Alice failed to verify Bob's confirmation tag (tau3)")

        transcript = self.ct1 + self.ct2 + self.tau1 + self.ct_star + self.qkd_key_id.encode("utf-8") + self.tau2 + tau3

        return HandshakeResult(k2h, self.security_mode, transcript)


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
    ) -> None:
        self.id_a = id_a
        self.pk_a = pk_a
        self.id_b = id_b
        self.pk_b = pk_b
        self.sk_b = sk_b
        self.algorithm = algorithm
        self.mitigation_mgr = mitigation_mgr or MitigationManager()
        self.kem = OQSKEM(algorithm)

    def message2(self, ct1: bytes) -> tuple[bytes, bytes, bytes]:
        """Message 2: Bob receives ct1, generates ephemeral keypair, decapsulates k1, encapsulates k2."""
        self.ct1 = ct1
        
        # Ephemeral KEM
        self.kp_e = self.kem.generate_keypair()
        
        # Decapsulate k1
        self.k1 = self.kem.decapsulate(self.sk_b, ct1)
        
        # Encapsulate Alice's static key
        self.ct2, self.k2 = self.kem.encapsulate(self.pk_a)
        
        s = ct1 + self.ct2
        
        # Tag tau1 using k1
        self.tau1 = hmac_sha256_tag(self.k1, self.kp_e.public_key + s + b"A")
        
        return self.kp_e.public_key, self.tau1, self.ct2

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
                k_qkd = qkd_pool_client_fn(qkd_key_id)
            else:
                k_qkd = None
        else:
            k_qkd = None
            security_mode = "SECURITY_LEVEL_DEGRADED_PQC_ONLY"

        # Multi-input KDF
        c_kem = serialize_fields(
            self.id_a, self.pk_a, self.id_b, self.pk_b, self.kp_e.public_key, self.k1, self.k2, k_star
        )
        c_qkd = serialize_fields(self.id_a, self.id_b, qkd_key_id)

        sigma_qkd = k_qkd if k_qkd is not None else b""

        k_h = rokdf(k_star, c_kem, sigma_qkd, c_qkd)
        k1h = k_h[:32]
        k2h = k_h[32:]

        # Compute tau3 confirmation tag
        tau3 = hmac_sha256_tag(
            k1h,
            serialize_fields(
                self.k1, qkd_key_id, self.kp_e.public_key, self.tau1, self.k2, tau2
            ),
        )

        transcript = self.ct1 + self.ct2 + self.tau1 + ct_star + qkd_key_id.encode("utf-8") + tau2 + tau3

        return tau3, HandshakeResult(k2h, security_mode, transcript)
