from jam_vrf import ietf_verify
import pytest
import json


def test_signature_verification():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ietf"]
    public_key = bytes.fromhex(mock["public_key"])
    data = bytes.fromhex(mock["data"])
    ad = bytes.fromhex(mock["additional_data"])
    signature = bytes.fromhex(mock["signature"])

    # verify valid signature
    ietf_verify(public_key, data, ad, signature)

    # verify invalid signature (wrong data)
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(public_key, b"wrong_data", ad, signature)

    # verify invalid signature (wrong ad)
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(public_key, data, b"wrong_ad", signature)
