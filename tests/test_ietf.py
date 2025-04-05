from jam_vrf import ietf_verify

def test_ietf_signature_verify():
    # vector 7 from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
    public_key = bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
    data = bytes.fromhex("42616e646572736e6174636820766563746f72")
    ad = bytes.fromhex("1f42")
    signature = bytes.fromhex("6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f166dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609")
    ietf_verify(public_key, data, ad, signature)
