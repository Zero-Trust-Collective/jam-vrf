"""Tests for RingVRF functionality in the cryptography module.

This module contains tests for the RingVRF class,
verifying its sign/verify functionality works as expected.
"""

import pytest
from cryptography import KeyPairVRF, RingVRF, VRFOutput, RingVRFProof

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
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, message, ad)
    
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
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, message, ad)
    
    # Get bytes
    proof_bytes = proof.bytes()
    output_bytes = output.bytes()
    
    # Create new objects from bytes
    reconstructed_proof = RingVRFProof(proof_bytes)
    reconstructed_output = VRFOutput(output_bytes)
    
    # Verify reconstructed objects work
    result = ring_vrf.verify(message, ad, reconstructed_proof, reconstructed_output)
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

def test_ring_vrf_sign_verify():
    """Test RingVRF sign and verify functionality.
    
    This test:
    1. Creates multiple key pairs to form a ring
    2. Signs a message using RingVRF.prove with one of the keys
    3. Verifies the signature using RingVRF.verify with the ring of public keys
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
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, message, ad)
    
    # Verify the proof
    result = ring_vrf.verify(message, ad, proof, output)
    assert result is True

def test_ring_vrf_invalid_index():
    """Test RingVRF fails with invalid index."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"additional data"
    
    ring_vrf = RingVRF(ring_public_keys)
    
    # Test with index >= ring size
    with pytest.raises(ValueError):
        ring_vrf.prove(key_pair1, 2, message, ad)
    
    # Test with index that doesn't match the key
    proof, output = ring_vrf.prove(key_pair1, 1, message, ad)
    with pytest.raises(ValueError):
        ring_vrf.verify(message, ad, proof, output)

def test_ring_vrf_different_message():
    """Test RingVRF verify fails with different message.
    
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
    
    # Get proof and output using prove
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, message, ad)
    
    # Try to verify with different message
    different_message = b"different message"
    with pytest.raises(ValueError):
        ring_vrf.verify(different_message, ad, proof, output)

def test_ring_vrf_invalid_ring():
    """Test RingVRF fails with invalid ring.
    
    This test verifies that the RingVRF operations fail when trying to
    use an empty ring of public keys.
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Test with empty ring
    empty_ring = []
    
    # Attempt to create RingVRF with empty ring should fail
    with pytest.raises(ValueError):
        RingVRF(empty_ring)

def test_ring_vrf_different_ad():
    """Test RingVRF verify fails with different additional data."""
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
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, message, ad)
    
    different_ad = b"different ad"
    with pytest.raises(ValueError):
        ring_vrf.verify(message, different_ad, proof, output)

def test_ring_vrf_large_ring():
    """Test RingVRF with a larger ring size (100 keys)."""
    # Create 100 key pairs
    key_pairs = [KeyPairVRF() for _ in range(100)]
    ring_public_keys = [kp.public_key_bytes() for kp in key_pairs]
    
    message = b"test message"
    ad = b"additional data"
    
    ring_vrf = RingVRF(ring_public_keys)
    
    # Test with first key
    proof, output = ring_vrf.prove(key_pairs[0], 0, message, ad)
    result = ring_vrf.verify(message, ad, proof, output)
    assert result is True
    
    # Test with last key
    proof, output = ring_vrf.prove(key_pairs[-1], 99, message, ad)
    result = ring_vrf.verify(message, ad, proof, output)
    assert result is True

def test_ring_vrf_empty_message_and_ad():
    """Test RingVRF with empty message and additional data."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, b"", b"")
    result = ring_vrf.verify(b"", b"", proof, output)
    assert result is True

def test_ring_vrf_large_message_and_ad():
    """Test RingVRF with large message and additional data."""
    large_message = b"x" * 1000000  # 1MB message
    large_ad = b"y" * 1000000  # 1MB additional data
    
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    ring_vrf = RingVRF(ring_public_keys)
    proof, output = ring_vrf.prove(key_pair1, 0, large_message, large_ad)
    result = ring_vrf.verify(large_message, large_ad, proof, output)
    assert result is True
