"""Tests for single VRF functionality in the pyvrfs module.

This module contains tests for the SingleVRFProver and SingleVRFVerifier classes,
verifying their prove/verify functionality works as expected.
"""

import pytest
from pyvrfs import KeyPairVRF, SingleVRFProver, SingleVRFVerifier, VRFOutput, SingleVRFProof

def test_single_vrf_proof_output_bytes():
    """Test accessing bytes from SingleVRFProof and VRFOutput.
    
    This test verifies that:
    1. proof.bytes() returns non-empty bytes
    2. output.bytes() returns non-empty bytes
    3. Multiple calls return the same bytes
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"additional data"
    
    prover = SingleVRFProver()
    proof, output = prover.prove(key_pair, message, ad)
    
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

def test_single_vrf_from_bytes():
    """Test creating SingleVRFProof and VRFOutput from bytes.
    
    This test verifies that:
    1. Can create SingleVRFProof from bytes
    2. Can create VRFOutput from bytes
    3. Reconstructed objects work correctly in verification
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"additional data"
    
    prover = SingleVRFProver()
    proof, output = prover.prove(key_pair, message, ad)
    
    # Get bytes
    proof_bytes = proof.bytes()
    output_bytes = output.bytes()
    
    # Create new objects from bytes
    reconstructed_proof = SingleVRFProof(proof_bytes)
    reconstructed_output = VRFOutput(output_bytes)
    
    # Verify reconstructed objects work
    public_key_bytes = key_pair.public_key_bytes()
    verifier = SingleVRFVerifier()
    result = verifier.verify(public_key_bytes, message, ad, reconstructed_output, reconstructed_proof)
    assert result is True

def test_single_vrf_invalid_bytes():
    """Test error handling when creating from invalid bytes."""
    # Test with empty bytes
    with pytest.raises(ValueError):
        SingleVRFProof(b"")
    with pytest.raises(RuntimeError):
        VRFOutput(b"")
    
    # Test with invalid bytes
    invalid_bytes = b"invalid bytes"
    with pytest.raises(ValueError):
        SingleVRFProof(invalid_bytes)
    with pytest.raises(RuntimeError):
        VRFOutput(invalid_bytes)

def test_single_vrf_prove_verify():
    """Test SingleVRF prove and verify functionality.
    
    This test:
    1. Creates a new key pair
    2. Signs a message using SingleVRFProver.prove
    3. Verifies the signature using SingleVRFVerifier.verify
    """
    # Create key pair
    key_pair = KeyPairVRF()
    
    # Test message and additional data
    message = b"test message"
    ad = b"additional data"
    
    # Get proof and output using prove
    prover = SingleVRFProver()
    proof, output = prover.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Verify the proof
    verifier = SingleVRFVerifier()
    result = verifier.verify(public_key_bytes, message, ad, output, proof)
    assert result is True

def test_single_vrf_different_message():
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
    prover = SingleVRFProver()
    proof, output = prover.prove(key_pair, message, ad)
    
    # Get public key bytes
    public_key_bytes = key_pair.public_key_bytes()
    
    # Try to verify with different message
    different_message = b"different message"
    verifier = SingleVRFVerifier()
    with pytest.raises(ValueError):
        verifier.verify(public_key_bytes, different_message, ad, output, proof)

def test_single_vrf_different_ad():
    """Test SingleVRF verify fails with different additional data.
    
    This test verifies that the verification fails when trying to verify
    a signature with different additional data than what was used for signing.
    """
    key_pair = KeyPairVRF()
    message = b"test message"
    ad = b"original ad"
    
    prover = SingleVRFProver()
    proof, output = prover.prove(key_pair, message, ad)
    public_key_bytes = key_pair.public_key_bytes()
    
    different_ad = b"different ad"
    verifier = SingleVRFVerifier()
    with pytest.raises(ValueError):
        verifier.verify(public_key_bytes, message, different_ad, output, proof)

def test_single_vrf_empty_message_and_ad():
    """Test SingleVRF with empty message and additional data."""
    key_pair = KeyPairVRF()
    prover = SingleVRFProver()
    verifier = SingleVRFVerifier()
    
    proof, output = prover.prove(key_pair, b"", b"")
    result = verifier.verify(key_pair.public_key_bytes(), b"", b"", output, proof)
    assert result is True

def test_single_vrf_large_message_and_ad():
    """Test SingleVRF with large message and additional data."""
    large_message = b"x" * 1000000  # 1MB message
    large_ad = b"y" * 1000000  # 1MB additional data
    
    key_pair = KeyPairVRF()
    prover = SingleVRFProver()
    verifier = SingleVRFVerifier()
    
    proof, output = prover.prove(key_pair, large_message, large_ad)
    result = verifier.verify(key_pair.public_key_bytes(), large_message, large_ad, output, proof)
    assert result is True
