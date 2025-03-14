"""Tests for ring VRF functionality in the pyvrfs module.

This module contains tests for the RingVRFProver and RingVRFVerifier classes,
verifying their prove/verify functionality works as expected.
"""

import pytest
from pyvrfs import (
    KeyPairVRF, RingVRFProver, RingVRFVerifier, VRFOutput, RingVRFProof,
    get_ring_commitment
)

def test_ring_vrf_proof_output_bytes():
    """Test accessing bytes from RingVRFProof and VRFOutput.
    
    This test verifies that:
    1. proof.bytes() returns non-empty bytes
    2. output.bytes() returns non-empty bytes
    3. Multiple calls return the same bytes
    """
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"additional data"
    
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    proof, output = prover.prove(key_pair1, message, ad)
    
    # Test proof bytes
    proof_bytes = proof.bytes()
    assert isinstance(proof_bytes, bytes)
    assert len(proof_bytes) > 0
    
    # Test output bytes
    output_bytes = output.bytes()
    assert isinstance(output_bytes, bytes)
    assert len(output_bytes) > 0
    
    # Test multiple calls return same bytes
    assert proof.bytes() == proof_bytes
    assert output.bytes() == output_bytes

def test_ring_vrf_from_bytes():
    """Test creating RingVRFProof and VRFOutput from bytes.
    
    This test verifies that:
    1. Can create RingVRFProof from bytes
    2. Can create VRFOutput from bytes
    3. Reconstructed objects work correctly in verification
    """
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"additional data"
    
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    proof, output = prover.prove(key_pair1, message, ad)
    
    # Get bytes
    proof_bytes = proof.bytes()
    output_bytes = output.bytes()
    
    # Create new objects from bytes
    reconstructed_proof = RingVRFProof(proof_bytes)
    reconstructed_output = VRFOutput(output_bytes)
    
    # Verify reconstructed objects work
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    result = verifier.verify(message, ad, reconstructed_output, reconstructed_proof)
    assert result is True

def test_ring_vrf_invalid_bytes():
    """Test error handling when creating from invalid bytes."""
    # Test with empty bytes
    with pytest.raises(RuntimeError):
        RingVRFProof(b"")
    with pytest.raises(RuntimeError):
        VRFOutput(b"")
    
    # Test with invalid bytes
    invalid_bytes = b"invalid bytes"
    with pytest.raises(RuntimeError):
        RingVRFProof(invalid_bytes)
    with pytest.raises(RuntimeError):
        VRFOutput(invalid_bytes)

def test_ring_vrf_prove_verify():
    """Test ring VRF prove and verify functionality.
    
    This test:
    1. Creates multiple key pairs to form a ring
    2. Signs a message using RingVRFProver.prove with one of the keys
    3. Verifies the signature using RingVRFVerifier.verify
    """
    # Create multiple key pairs for the ring
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    key_pair3 = KeyPairVRF()
    
    # Get public keys
    pk1_bytes = key_pair1.public_key_bytes()
    pk2_bytes = key_pair2.public_key_bytes()
    pk3_bytes = key_pair3.public_key_bytes()
    
    # Create ring of public keys
    ring_public_keys = [pk1_bytes, pk2_bytes, pk3_bytes]
    
    # Test message and additional data
    message = b"test message"
    ad = b"additional data"
    
    # Get commitment and create prover/verifier
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    # Generate and verify proof
    proof, output = prover.prove(key_pair1, message, ad)
    result = verifier.verify(message, ad, output, proof)
    assert result is True

def test_ring_vrf_invalid_index():
    """Test ring VRF fails with invalid index."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"additional data"
    
    # Test with index >= ring size
    with pytest.raises(ValueError):
        RingVRFProver(ring_public_keys, 2)
    
    # Test with index that doesn't match the key
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 1)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    proof, output = prover.prove(key_pair1, message, ad)
    with pytest.raises(ValueError):
        verifier.verify(message, ad, output, proof)

def test_ring_vrf_different_message():
    """Test ring VRF verify fails with different message.
    
    This test verifies that the verification fails when trying to verify
    a signature with a different message than what was signed.
    """
    # Create multiple key pairs for the ring
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    key_pair3 = KeyPairVRF()
    
    # Get public keys
    pk1_bytes = key_pair1.public_key_bytes()
    pk2_bytes = key_pair2.public_key_bytes()
    pk3_bytes = key_pair3.public_key_bytes()
    
    # Create ring of public keys
    ring_public_keys = [pk1_bytes, pk2_bytes, pk3_bytes]
    
    # Original message and additional data
    message = b"original message"
    ad = b"additional data"
    
    # Get commitment and create prover/verifier
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    # Generate proof
    proof, output = prover.prove(key_pair1, message, ad)
    
    # Try to verify with different message
    different_message = b"different message"
    with pytest.raises(ValueError):
        verifier.verify(different_message, ad, output, proof)

def test_ring_vrf_invalid_ring():
    """Test ring VRF fails with invalid ring.
    
    This test verifies that the ring VRF operations fail when trying to
    use an empty ring of public keys.
    """
    # Test with empty ring
    empty_ring = []
    
    # Attempt to get commitment with empty ring should fail
    with pytest.raises(ValueError):
        get_ring_commitment(empty_ring)

def test_ring_vrf_different_ad():
    """Test ring VRF verify fails with different additional data."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    key_pair3 = KeyPairVRF()
    
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes(),
        key_pair3.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"original ad"
    
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    proof, output = prover.prove(key_pair1, message, ad)
    
    different_ad = b"different ad"
    with pytest.raises(ValueError):
        verifier.verify(message, different_ad, output, proof)

def test_ring_vrf_empty_message_and_ad():
    """Test ring VRF with empty message and additional data."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    proof, output = prover.prove(key_pair1, b"", b"")
    result = verifier.verify(b"", b"", output, proof)
    assert result is True

def test_ring_vrf_large_message_and_ad():
    """Test ring VRF with large message and additional data."""
    large_message = b"x" * 1000000  # 1MB message
    large_ad = b"y" * 1000000  # 1MB additional data
    
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    commitment = get_ring_commitment(ring_public_keys)
    prover = RingVRFProver(ring_public_keys, 0)
    verifier = RingVRFVerifier(commitment, len(ring_public_keys))
    
    proof, output = prover.prove(key_pair1, large_message, large_ad)
    result = verifier.verify(large_message, large_ad, output, proof)
    assert result is True
