from jam_vrf import ietf_verify
import pytest
import json


def test_signature_verification():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ietf"]

    # verify valid signature
    ietf_verify(
        bytes.fromhex(mock["public_key"]),
        bytes.fromhex(mock["data"]),
        bytes.fromhex(mock["additional_data"]),
        bytes.fromhex(mock["signature"]),
    )

    # verify invalid signature (wrong data)
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(
            bytes.fromhex(mock["public_key"]),
            b"wrong_data",  # data is different from what was signed
            bytes.fromhex(mock["additional_data"]),
            bytes.fromhex(mock["signature"]),
        )

    # verify invalid signature (wrong ad)
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(
            bytes.fromhex(mock["public_key"]),
            bytes.fromhex(mock["data"]),
            b"wrong_ad",  # ad is different from what was signed
            bytes.fromhex(mock["signature"]),
        )
