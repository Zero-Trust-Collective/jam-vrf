"""Tests for SingleVRF functionality in the cryptography module.

This module contains tests for the SingleVRF class,
verifying its sign/verify functionality works as expected.
"""

import pytest
from cryptography import KeyPairVRF, SingleVRF

def test_fallback_vrf_proof_output_bytes():
    """Test accessing proof and output bytes from SingleVRFOutput.
    
    This test verifies that:
    1. proof_bytes() returns non-empty bytes
    2. output_bytes() returns non-empty bytes
    3. Multiple calls return the same bytes
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"additional data"
    
    fallback_vrf = SingleVRF()
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

def test_fallback_vrf_sign_verify():
    """Test SingleVRF sign and verify functionality.
    
    This test:
    1. Creates a new key pair
    2. Signs a message using SingleVRF.prove
    3. Verifies the signature using SingleVRF.verify
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Test message and additional data
    message = b"test message"
    ad = b"additional data"
    
    # Get proof and output using prove
    fallback_vrf = SingleVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Verify the proof
    result = fallback_vrf.verify(public_key_bytes, message, ad, proof_and_output)
    assert result is True

def test_fallback_vrf_different_message():
    """Test SingleVRF verify fails with different message.
    
    This test verifies that the verification fails when trying to verify
    a signature with a different message than what was signed.
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Original message and additional data
    message = b"original message"
    ad = b"additional data"
    
    # Get proof and output using prove
    fallback_vrf = SingleVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Try to verify with different message
    different_message = b"different message"
    with pytest.raises(ValueError):
        fallback_vrf.verify(public_key_bytes, different_message, ad, proof_and_output)

def test_fallback_vrf_different_ad():
    """Test SingleVRF verify fails with different additional data.
    
    This test verifies that the verification fails when trying to verify
    a signature with different additional data than what was used for signing.
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"original ad"
    
    fallback_vrf = SingleVRF()
    proof_and_output = fallback_vrf.prove(key_pair, message, ad)
    public_key_bytes = key_pair.public_key_bytes()
    
    different_ad = b"different ad"
    with pytest.raises(ValueError):
        fallback_vrf.verify(public_key_bytes, message, different_ad, proof_and_output)

def test_single_vrf_empty_message_and_ad():
    """Test SingleVRF with empty message and additional data."""
    key_pair = KeyPairVRF()
    fallback_vrf = SingleVRF()
    
    proof_and_output = fallback_vrf.prove(key_pair, b"", b"")
    result = fallback_vrf.verify(key_pair.public_key_bytes(), b"", b"", proof_and_output)
    assert result is True

def test_single_vrf_large_message_and_ad():
    """Test SingleVRF with large message and additional data."""
    large_message = b"x" * 1000000  # 1MB message
    large_ad = b"y" * 1000000  # 1MB additional data
    
    key_pair = KeyPairVRF()
    fallback_vrf = SingleVRF()
    
    proof_and_output = fallback_vrf.prove(key_pair, large_message, large_ad)
    result = fallback_vrf.verify(key_pair.public_key_bytes(), large_message, large_ad, proof_and_output)
    assert result is True
