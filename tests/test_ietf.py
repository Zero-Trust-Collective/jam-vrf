from jam_vrf import ietf_verify
import pytest

def test_valid_ietf_sig():
    # vector 7 from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
    public_key = bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
    data = bytes.fromhex("42616e646572736e6174636820766563746f72")
    ad = bytes.fromhex("1f42")
    signature = bytes.fromhex("6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f166dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609")
    ietf_verify(public_key, data, ad, signature)

def test_invalid_ietf_sig():
    # vector 7 from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
    # invalid signature sourced from vector 6: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L75-L78C17 
    public_key = bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
    data = bytes.fromhex("42616e646572736e6174636820766563746f72")
    ad = bytes.fromhex("1f42")
    signature = bytes.fromhex("9508104b820469687488d83f729288d9f70fc0523318beff44a47da10d490b3c4fa53519bd9d17acae4d1021416557d11b84dd4670b563770c14eb98161eaa080f7f9bee9077427f547e69b919cf8d63823c14b20085fd9516768e0f5e3d3f0e")
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(public_key, data, ad, signature)
