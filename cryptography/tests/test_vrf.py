"""Tests for VRF functionality in the cryptography module.

This module contains tests for both FallbackVRF and RingVRF classes,
verifying their sign/verify functionality works as expected.
"""

import pytest
from cryptography import KeyPairVRF, FallbackVRF, RingVRF

def test_fallback_vrf_proof_output_bytes():
    """Test accessing proof and output bytes from FallbackVRFOutput.
    
    This test verifies that:
    1. proof_bytes() returns non-empty bytes
    2. output_bytes() returns non-empty bytes
    3. Multiple calls return the same bytes
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"additional data"
    
    fallback_vrf = FallbackVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    
    # Test proof bytes
    proof_bytes = proof_and_output.proof_bytes()
    assert isinstance(proof_bytes, bytes)
    assert len(proof_bytes) > 0
    
    # Test output bytes
    output_bytes = proof_and_output.output_bytes()
    assert isinstance(output_bytes, bytes)
    assert len(output_bytes) > 0
    
    # Test multiple calls return same bytes
    assert proof_and_output.proof_bytes() == proof_bytes
    assert proof_and_output.output_bytes() == output_bytes

def test_ring_vrf_proof_output_bytes():
    """Test accessing proof and output bytes from RingVRFOutput.
    
    This test verifies that:
    1. proof_bytes() returns non-empty bytes
    2. output_bytes() returns non-empty bytes
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
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    
    # Test proof bytes
    proof_bytes = proof_and_output.proof_bytes()
    assert isinstance(proof_bytes, bytes)
    assert len(proof_bytes) > 0
    
    # Test output bytes
    output_bytes = proof_and_output.output_bytes()
    assert isinstance(output_bytes, bytes)
    assert len(output_bytes) > 0
    
    # Test multiple calls return same bytes
    assert proof_and_output.proof_bytes() == proof_bytes
    assert proof_and_output.output_bytes() == output_bytes

def test_fallback_vrf_sign_verify():
    """Test FallbackVRF sign and verify functionality.
    
    This test:
    1. Creates a new key pair
    2. Signs a message using FallbackVRF.prove
    3. Verifies the signature using FallbackVRF.verify
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Test message and additional data
    message = b"test message"
    ad = b"additional data"
    
    # Get proof and output using prove
    fallback_vrf = FallbackVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Verify the proof
    result = fallback_vrf.verify(public_key_bytes, message, ad, proof_and_output)
    assert result is True

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
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    
    # Verify the proof
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True

def test_ring_vrf_different_indices():
    """Test RingVRF with different indices for the same key.
    
    This test verifies that:
    1. The same key can be used with different indices in the ring
    2. The proofs are unique for different indices
    3. All proofs verify correctly
    """
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes(),
        key_pair1.public_key_bytes()  # Duplicate key
    ]
    
    message = b"test message"
    ad = b"additional data"
        
    # Create proofs with different indices for the same key
    ring_vrf = RingVRF()
    proof1 = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    proof2 = ring_vrf.prove(key_pair1, ring_public_keys, 2, message, ad)
    
    # Verify both proofs work
    assert ring_vrf.verify(ring_public_keys, message, ad, proof1)
    assert ring_vrf.verify(ring_public_keys, message, ad, proof2)
    
    # Verify proofs are different
    assert proof1.proof_bytes() != proof2.proof_bytes()

    # Verify outputs are same
    assert proof1.output_bytes() == proof2.output_bytes()

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
    
    ring_vrf = RingVRF()
    
    # Test with index >= ring size
    with pytest.raises(ValueError):
        test = ring_vrf.prove(key_pair1, ring_public_keys, 2, message, ad)
    
    # Test with index that doesn't match the key
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 1, message, ad)
    with pytest.raises(ValueError):
        ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)

def test_fallback_vrf_different_message():
    """Test FallbackVRF verify fails with different message.
    
    This test verifies that the verification fails when trying to verify
    a signature with a different message than what was signed.
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Original message and additional data
    message = b"original message"
    ad = b"additional data"
    
    # Get proof and output using prove
    fallback_vrf = FallbackVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Try to verify with different message
    different_message = b"different message"
    with pytest.raises(ValueError):
        fallback_vrf.verify(public_key_bytes, different_message, ad, proof_and_output)

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
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    
    # Try to verify with different message
    different_message = b"different message"
    with pytest.raises(ValueError):
        ring_vrf.verify(ring_public_keys, different_message, ad, proof_and_output)

def test_ring_vrf_invalid_ring():
    """Test RingVRF fails with invalid ring.
    
    This test verifies that the RingVRF operations fail when trying to
    use an empty ring of public keys.
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Test with empty ring
    empty_ring = []
    message = b"test message"
    ad = b"additional data"
    
    # Attempt to prove with empty ring should fail
    ring_vrf = RingVRF()
    with pytest.raises(ValueError):
        ring_vrf.prove(key_pair, empty_ring, 0, message, ad)

def test_fallback_vrf_different_ad():
    """Test FallbackVRF verify fails with different additional data.
    
    This test verifies that the verification fails when trying to verify
    a signature with different additional data than what was used for signing.
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"original ad"
    
    fallback_vrf = FallbackVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    public_key_bytes = key_pair.public_key_bytes()
    
    different_ad = b"different ad"
    with pytest.raises(ValueError):
        fallback_vrf.verify(public_key_bytes, message, different_ad, proof_and_output)

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
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    
    different_ad = b"different ad"
    with pytest.raises(ValueError):
        ring_vrf.verify(ring_public_keys, message, different_ad, proof_and_output)

def test_ring_vrf_large_ring():
    """Test RingVRF with a larger ring size (100 keys)."""
    # Create 100 key pairs
    key_pairs = [KeyPairVRF() for _ in range(100)]
    ring_public_keys = [kp.public_key_bytes() for kp in key_pairs]
    
    message = b"test message"
    ad = b"additional data"
    
    # Test with first key
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pairs[0], ring_public_keys, 0, message, ad)
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True
    
    # Test with last key
    proof_and_output = ring_vrf.prove(key_pairs[-1], ring_public_keys, 99, message, ad)
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True

def test_ring_vrf_reordered_ring():
    """Test RingVRF with keys in different order than signing key."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    key_pair3 = KeyPairVRF()
    
    # Original order
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes(),
        key_pair3.public_key_bytes()
    ]
    
    message = b"test message"
    ad = b"additional data"
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    
    # Verify with reordered ring
    reordered_ring = [
        key_pair3.public_key_bytes(),
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    with pytest.raises(ValueError):
        ring_vrf.verify(reordered_ring, message, ad, proof_and_output)

def test_ring_vrf_duplicate_keys():
    """Test RingVRF works with duplicate keys in ring."""
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    
    pk1_bytes = key_pair1.public_key_bytes()
    pk2_bytes = key_pair2.public_key_bytes()
    
    # Create ring with duplicate key
    ring_public_keys = [pk1_bytes, pk2_bytes, pk1_bytes]
    
    message = b"test message"
    ad = b"additional data"
    
    ring_vrf = RingVRF()
    
    # Test signing with first occurrence of key1
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, message, ad)
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True
    
    # Test signing with second occurrence of key1
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 2, message, ad)
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True
    
    # Test signing with key2
    proof_and_output = ring_vrf.prove(key_pair2, ring_public_keys, 1, message, ad)
    result = ring_vrf.verify(ring_public_keys, message, ad, proof_and_output)
    assert result is True

def test_vrf_empty_message_and_ad():
    """Test both VRFs with empty message and additional data."""
    # Test FallbackVRF
    key_pair = KeyPairVRF()
    fallback_vrf = FallbackVRF()
    
    proof_and_output = fallback_vrf.prove(key_pair, b"", b"")
    result = fallback_vrf.verify(key_pair.public_key_bytes(), b"", b"", proof_and_output)
    assert result is True
    
    # Test RingVRF
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, b"", b"")
    result = ring_vrf.verify(ring_public_keys, b"", b"", proof_and_output)
    assert result is True

def test_vrf_large_message_and_ad():
    """Test both VRFs with large message and additional data."""
    large_message = b"x" * 1000000  # 1MB message
    large_ad = b"y" * 1000000  # 1MB additional data
    
    # Test FallbackVRF
    key_pair = KeyPairVRF()
    fallback_vrf = FallbackVRF()
    
    proof_and_output = fallback_vrf.prove(key_pair, large_message, large_ad)
    result = fallback_vrf.verify(key_pair.public_key_bytes(), large_message, large_ad, proof_and_output)
    assert result is True
    
    # Test RingVRF
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    
    ring_vrf = RingVRF()
    proof_and_output = ring_vrf.prove(key_pair1, ring_public_keys, 0, large_message, large_ad)
    result = ring_vrf.verify(ring_public_keys, large_message, large_ad, proof_and_output)
    assert result is True
