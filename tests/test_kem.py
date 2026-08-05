import pytest
from qkd_hake.crypto.kem import OQSKEM, SUPPORTED_ALGORITHMS

@pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
def test_kem_algorithm_roundtrip(algorithm: str) -> None:
    # Initialize the wrapper
    kem = OQSKEM(algorithm)
    
    # 1. Generate keypair
    keypair = kem.generate_keypair()
    assert keypair.public_key is not None
    assert len(keypair.public_key) > 0
    assert keypair.secret_key is not None
    assert len(keypair.secret_key) > 0
    
    # 2. Encapsulate
    ciphertext, shared_secret_sender = kem.encapsulate(keypair.public_key)
    assert ciphertext is not None
    assert len(ciphertext) > 0
    assert shared_secret_sender is not None
    assert len(shared_secret_sender) > 0
    
    # 3. Decapsulate
    shared_secret_receiver = kem.decapsulate(keypair.secret_key, ciphertext)
    assert shared_secret_receiver is not None
    assert len(shared_secret_receiver) > 0
    
    # 4. Verify shared secret match
    assert shared_secret_sender == shared_secret_receiver
