from jam_vrf import ietf_verify
import pytest
import json


def test_valid_ietf_sig():
    # vector 7 from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81

    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ietf"]["valid_signature"]

    ietf_verify(
        bytes.fromhex(mock["public_key"]),
        bytes.fromhex(mock["data"]),
        bytes.fromhex(mock["additional_data"]),
        bytes.fromhex(mock["signature"]),
    )


def test_invalid_ietf_sig():
    # vector 7 from https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L81
    # invalid signature sourced from vector 6: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ietf.json#L75-L78C17

    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ietf"]["invalid_signature"]

    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(
            bytes.fromhex(mock["public_key"]),
            bytes.fromhex(mock["data"]),
            bytes.fromhex(mock["additional_data"]),
            bytes.fromhex(mock["signature"]),
        )
