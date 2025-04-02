"""Tests for ring commitment functionality.

This module contains tests for the ring commitment functionality
using the get_ring_commitment function.
"""

import pytest
from pyvrfs import KeyPairVRF, get_ring_commitment

def test_ring_commitment():
    """Test ring commitment generation with known input/output values."""
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

    # Expected output commitment
    expected_commitment = bytes.fromhex("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    result = get_ring_commitment(public_keys)
    
    assert result == expected_commitment, f"Expected {expected_commitment.hex()}, but got {result.hex()}"

def test_ring_commitment_eight_keys():
    """Test ring commitment generation with a known 8-key ring."""
    # test vector sourced from: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ring.json#L123
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

    # Expected output commitment
    expected_commitment = bytes.fromhex("a359e70e307799b111ad89b162b4260fb4a96ebf4232e8b02d396033498d4216305ed9cff3584a4c68f03ab3df87243a80bfc965633efc23c82ca064afe105baacccbf23e47b543d16c3c4466a83242a77acc16f79b8710051b5e97c85319cf392e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    result = get_ring_commitment(public_keys)
    
    assert result == expected_commitment, f"Expected {expected_commitment.hex()}, but got {result.hex()}"
