from pyvrf import (
    RingVRFVerifier, VRFOutput, RingVRFProof,
    get_ring_commitment
)

def test_ring_commitment():
    # test vector sourced from: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ring.json#L123
    # public keys
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

    # expected output commitment
    expected_commitment = bytes.fromhex("a359e70e307799b111ad89b162b4260fb4a96ebf4232e8b02d396033498d4216305ed9cff3584a4c68f03ab3df87243a80bfc965633efc23c82ca064afe105baacccbf23e47b543d16c3c4466a83242a77acc16f79b8710051b5e97c85319cf392e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")

    result = get_ring_commitment(public_keys)
    
    assert result == expected_commitment, f"Expected {expected_commitment.hex()}, but got {result.hex()}"
