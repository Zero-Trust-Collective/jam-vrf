"""Tests for Bandersnatch root generation functionality.

This module contains tests for the bandersnatch root generation
functionality of the RingVRF class.
"""

import pytest
from cryptography import KeyPairVRF, RingVRF

def test_ring_vrf_bandersnatch_root():
    """Test RingVRF bandersnatch root generation.
    
    This test verifies that:
    1. Root can be generated from valid ring
    2. Root is non-empty bytes
    3. Same ring produces same root
    4. Different rings produce different roots
    5. Empty ring raises error
    """
    # Create key pairs
    key_pair1 = KeyPairVRF()
    key_pair2 = KeyPairVRF()
    key_pair3 = KeyPairVRF()
    
    # Create ring of public keys
    ring_public_keys = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes(),
        key_pair3.public_key_bytes()
    ]
    
    ring_vrf = RingVRF(ring_public_keys)
    
    # Test basic functionality
    root = ring_vrf.root()
    assert isinstance(root, bytes)
    assert len(root) > 0
    
    # Test same ring produces same root
    ring_vrf2 = RingVRF(ring_public_keys)
    root2 = ring_vrf2.root()
    assert root == root2
    
    # Test different ring produces different root
    different_ring = [
        key_pair1.public_key_bytes(),
        key_pair2.public_key_bytes()
    ]
    different_ring_vrf = RingVRF(different_ring)
    different_root = different_ring_vrf.root()
    assert root != different_root
    
    # Test empty ring raises error
    with pytest.raises(ValueError):
        RingVRF([])

def test_ring_vrf_bandersnatch_root_no_epoch_change():
    """Test RingVRF bandersnatch root generation with known input/output values."""
    # First create a key pair to see the format of its public key
    key_pair = KeyPairVRF()
    example_pk = key_pair.public_key_bytes()
    print(f"Example public key format: {example_pk.hex()}, length: {len(example_pk)}")
    
    # Known public keys
    public_keys = [
        bytes.fromhex("5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d"),
        bytes.fromhex("3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0"),
        bytes.fromhex("aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc"),
        bytes.fromhex("7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33"),
        bytes.fromhex("48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3"),
        bytes.fromhex("f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d")
    ]

    # Expected output ring
    expected_ring = bytes.fromhex("a949a60ad754d683d398a0fb674a9bbe525ca26b0b0b9c8d79f210291b40d286d9886a9747a4587d497f2700baee229ca72c54ad652e03e74f35f075d0189a40d41e5ee65703beb5d7ae8394da07aecf9056b98c61156714fd1d9982367bee2992e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    ring_vrf = RingVRF(public_keys)
    result = ring_vrf.root()
    
    assert result == expected_ring, f"Expected {expected_ring.hex()}, but got {result.hex()}"

def test_ring_vrf_bandersnatch_root_epoch_change():
    """Test RingVRF bandersnatch root generation with known input/output values."""
    # First create a key pair to see the format of its public key
    key_pair = KeyPairVRF()
    example_pk = key_pair.public_key_bytes()
    print(f"Example public key format: {example_pk.hex()}, length: {len(example_pk)}")
    
    # Known public keys
    public_keys = [
        bytes.fromhex("aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc"),
        bytes.fromhex("f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d"),
        bytes.fromhex("5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d"),
        bytes.fromhex("48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3"),
        bytes.fromhex("3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0"),
        bytes.fromhex("7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33")
    ]

    # Expected output ring
    expected_ring = bytes.fromhex("b3750bba87e39fb38579c880ff3b5c4e0aa90df8ff8be1ddc5fdd615c6780955f8fd85d99fd92a3f1d4585eb7ae8d627b01dd76d41720d73c9361a1dd2e830871155834c55db72de38fb875a9470faedb8cae54b34f7bfe196a9caca00c2911592e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    ring_vrf = RingVRF(public_keys)
    result = ring_vrf.root()
    
    assert result == expected_ring, f"Expected {expected_ring.hex()}, but got {result.hex()}"

def test_ring_vrf_bandersnatch_root_eight_keys():
    """Test RingVRF bandersnatch root generation with a known 8-key ring."""
    # Known public keys
    public_keys = [
        bytes.fromhex("7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313"),
        bytes.fromhex("d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471"),
        bytes.fromhex("561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5"),
        bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623"),
        bytes.fromhex("4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c"),
        bytes.fromhex("86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437"),
        bytes.fromhex("ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b"),
        bytes.fromhex("3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9")
    ]

    # Expected output ring
    expected_ring = bytes.fromhex("8e311bb59a6d977b98e7f930aaef63d89a0203a7ba76af4bc20ddd37c394ef3fc23307b821a812dcda922174bc64ea1dae71419f21546acea495c4c7f25287ae5673cbc52b93841e0ccded9c1b0c3d67207602921942d97c814c4d955e91d4a192e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    ring_vrf = RingVRF(public_keys)
    result = ring_vrf.root()
    
    assert result == expected_ring, f"Expected {expected_ring.hex()}, but got {result.hex()}"
