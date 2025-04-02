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

def test_jam_ticket_verify():
    """Test ring VRF verification of a jam ticket.
    
    testvector sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
    
    This test:
    1. creates a RingVerifier from a commitment
    2. Verifies a ticket signature
    """

    # ticket vector
    attempt = 1
    signature = bytes.fromhex("1dfb7b61deee0c4a6899c1123e9e362f2b965079be576aebda0b7ac5e111186ec11372ea37a823a74a10a7d0c3b9b850d07ea9367f7560d0271a34125983fb0a4acb929b0817c4e3710915ea07e64d72198cbb2399e318940569d4c80ead4b5b39fa798e7a8327dcba940ffa77659b1850f877be7a439fc3a66191299d5ae92492d1a27a97455ca697913b3d7c7a9f95bfe58bda53a2641e4a0752f4efbb1a0417d77dedf11d514684f94b0729672a5808088b5445ceb540db00aa8934faa314a445e67a96d618c4fc1c100a69fa449cca1db6a7ac609d7bd04107f685411aa1bebecdb3897ed0d6c00b46a56381e5968b7520b215677afa1394464057709837dfb22b04b53c69011da7926c341cf6e77a2ed27912c40267c826cca53f876dad8a11740bbf7fec24eacf37246038a6da9d4fa923e40efb6d0a136ff2349fc1c6a1f0d199e87022d71cb503b9ea45a774988b0a3abe6f2a8bbeade7e72f14a27fd1fd2c34bf751a4397df18d16cea6ae40282ce51c36d85f5a90896070bcca248ecce27455c091c0f2e455ea83aaeac9b3c2df6cac95f34f7bd086746a414a3414f48f24f725ea802bc92a56a089f5af93122f85f7474380f3a3534553663ff34ea66f50ce876aa4bcec33ca5e7d0b16677c190d5c8365b3d55c3873b634ca53e988ca8860b97577f3b0265584b0544dde70556b35b86118c7b7c94232fb8fc30b6f407647ce39e40d0769e8a5d906f17a2ead9ab49ba3b3e669b3d48017ebf340e00a03ad82ad420ac3bc63b5f06cb15a0a938848a382ddaebabfe7b3ec13270f6c3e4c14aca85963f879bfc5937244bad613b0ed92f86205874a639fe758f3ab5c69222ea2460792c9c42732c74716886b2e8f9a155e5d439246bff0b21baf74f8e7b672c61f1328939f03be4e5d4dffa6f2d8231734a0ed8e82fef9dd00cb1ab1dfe37f0ddb12e1861570b6e4cab1ab80e774048227493bb8bad60df218b2a08e6d2230f1d040ce47e2d473d0e925b2a91abcb7f867ee2f41ad64409aa81a0937f130ebdf53e6ee61480c73708af790d1134b7a0b472573e1008b9c9d0ee95d40a3909d94e6cf0044d916ff9461844")
    ring_root = bytes.fromhex("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
    entropy = bytes.fromhex("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa")
    ring_size = 6

    # verify signature
    RingVRFVerifier(ring_root, ring_size).verify(
        "jam_ticket_seal".encode() + entropy + bytes([attempt]),
        b"",
        VRFOutput(signature[:32]),
        RingVRFProof(signature[32:]),
    )

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
