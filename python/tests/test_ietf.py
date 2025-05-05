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
        bytes.fromhex(mock["valid_signature"]),
    )

    # verify invalid signature
    with pytest.raises(ValueError, match="VRF verification failed"):
        ietf_verify(
            bytes.fromhex(mock["public_key"]),
            bytes.fromhex(mock["data"]),
            bytes.fromhex(mock["additional_data"]),
            bytes.fromhex(mock["invalid_signature"]),
        )
