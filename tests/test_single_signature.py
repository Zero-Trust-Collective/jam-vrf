from pyvrfs import (
    SingleVRFProof, SingleVRFVerifier, VRFOutput
)

def test_single_signature_verification():
    """ietf bandersnatch vrf signature verification"""
    # vector 1
    # https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L3
    public_key = bytes.fromhex("a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b")
    data = bytes.fromhex("")
    ad = bytes.fromhex("")
    output = VRFOutput(bytes.fromhex("e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f"))
    proof = SingleVRFProof(bytes.fromhex("439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101828bedd2ad95380b11f67a05ea0a76f0c3fef2bee9f043f4dffdddde09f55c01"))
    SingleVRFVerifier().verify(public_key, data, ad, output, proof)

    # vector 7
    # https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
    public_key = bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
    data = bytes.fromhex("42616e646572736e6174636820766563746f72")
    ad = bytes.fromhex("1f42")
    output = VRFOutput(bytes.fromhex("6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f16"))
    proof = SingleVRFProof(bytes.fromhex("6dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609"))
    SingleVRFVerifier().verify(public_key, data, ad, output, proof)
