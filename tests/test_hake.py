import pytest
import hmac
from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeError
from qkd_hake.mitigations.mitigations import MitigationManager, AdmissionControlError, QuotaExceededError


def test_hake_hybrid_handshake_success() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    # Mock QKD client functions
    qkd_key = b"q" * 32
    qkd_key_id = "test-qkd-key-id"

    def mock_qkd_client(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 100, "max_key_count": 100}
        elif action == "get":
            return qkd_key, qkd_key_id
        else:
            return qkd_key

    # Msg 1
    ct1, nonce_a = alice.message1()

    # Msg 2
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Msg 3
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=mock_qkd_client,
        allow_explicit_fallback=False
    )
    assert q_id == qkd_key_id

    # Msg 4
    tau3, bob_res = bob.message4(
        (ct_star, q_id, tau2),
        qkd_pool_client_fn=lambda kid: qkd_key
    )

    alice_res = alice.derive_and_verify(tau3)

    assert alice_res.session_key == bob_res.session_key
    assert alice_res.security_mode == "HYBRID_QKD"
    assert bob_res.security_mode == "HYBRID_QKD"
    assert len(alice_res.session_key) == 32


def test_hake_pqc_fallback_success() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    # Msg 1
    ct1, nonce_a = alice.message1()

    # Msg 2
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Msg 3 (No QKD Client, allow fallback = True)
    ct_star, q_id, tau2 = alice.message3(
        (pk_e, tau1, ct2, nonce_b),
        qkd_pool_client_fn=None,
        allow_explicit_fallback=True
    )
    assert q_id == ""

    # Msg 4
    tau3, bob_res = bob.message4(
        (ct_star, q_id, tau2),
        qkd_pool_client_fn=None
    )

    alice_res = alice.derive_and_verify(tau3)

    assert alice_res.session_key == bob_res.session_key
    assert alice_res.security_mode == "SECURITY_LEVEL_DEGRADED_PQC_ONLY"
    assert bob_res.security_mode == "SECURITY_LEVEL_DEGRADED_PQC_ONLY"


def test_hake_admission_control_triggers() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)

    # Mock QKD client returning <5% occupancy
    def mock_qkd_client_low_occupancy(action, key_id=None):
        if action == "status":
            return {"stored_key_count": 4, "max_key_count": 100}  # 4% occupancy
        return b"q" * 32, "id"

    # Msg 1 & 2 mock inputs
    ct1, nonce_a = alice.message1()
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Verify that when allow_explicit_fallback is False, it raises HandshakeError
    with pytest.raises(HandshakeError) as excinfo:
        alice.message3(
            (pk_e, tau1, ct2, nonce_b),
            qkd_pool_client_fn=mock_qkd_client_low_occupancy,
            allow_explicit_fallback=False
        )
    assert "below 5% admission control floor" in str(excinfo.value)


def test_hake_quota_limit_triggers() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    # Create mitigation manager with rate limit of 2 req/s
    mitigation_mgr = MitigationManager(rate_limit_per_peer=2)

    alice = AliceSession(
        "alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg,
        mitigation_mgr=mitigation_mgr
    )
    
    # 1st request
    mitigation_mgr.check_quota("alice")
    # 2nd request
    mitigation_mgr.check_quota("alice")
    
    # 3rd request should fail
    with pytest.raises(QuotaExceededError):
        mitigation_mgr.check_quota("alice")


def test_hake_tampering_fails() -> None:
    alg = "ML-KEM-512"
    kem = OQSKEM(alg)
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)

    ct1, nonce_a = alice.message1()
    pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))

    # Tamper with Message 2 MAC tag
    tampered_tau1 = bytearray(tau1)
    tampered_tau1[0] ^= 0xff
    tampered_tau1 = bytes(tampered_tau1)

    with pytest.raises(HandshakeError) as excinfo:
        alice.message3(
            (pk_e, tampered_tau1, ct2, nonce_b),
            qkd_pool_client_fn=None,
            allow_explicit_fallback=True
        )
    assert "Alice failed to verify Bob's Message 2 MAC" in str(excinfo.value)


@pytest.mark.parametrize('bad_key', [None, b'', bytes(31)])
@pytest.mark.parametrize('fallback', [True, False])
def test_alice_rejects_invalid_qkd_material(bad_key, fallback) -> None:
    kem = OQSKEM('ML-KEM-512')
    a, b = kem.generate_keypair(), kem.generate_keypair()
    alice = AliceSession('alice', a.public_key, a.secret_key, 'bob', b.public_key)
    bob = BobSession('alice', a.public_key, 'bob', b.public_key, b.secret_key)
    def delivery(action):
        return {'stored_key_count': 8, 'max_key_count': 8} if action == 'status' else (bad_key, 'id')
    with pytest.raises(HandshakeError, match='256-bit'):
        alice.message3(bob.message2(alice.message1()), delivery, fallback)


@pytest.mark.parametrize('retrieval', [None, lambda _: None, lambda _: b'', lambda _: bytes(31)])
def test_bob_rejects_missing_qkd_material(retrieval) -> None:
    kem = OQSKEM('ML-KEM-512')
    a, b = kem.generate_keypair(), kem.generate_keypair()
    alice = AliceSession('alice', a.public_key, a.secret_key, 'bob', b.public_key)
    bob = BobSession('alice', a.public_key, 'bob', b.public_key, b.secret_key)
    def delivery(action):
        return {'stored_key_count': 8, 'max_key_count': 8} if action == 'status' else (b'q' * 32, 'id')
    msg3 = alice.message3(bob.message2(alice.message1()), delivery, False)
    with pytest.raises(HandshakeError):
        bob.message4(msg3, retrieval)
