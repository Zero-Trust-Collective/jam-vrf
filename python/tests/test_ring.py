from jam_vrf import RingVerifier, get_ring_commitment
import pytest
import json


def test_ring_commitment():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["commitment"]

    # compose list of public key bytes
    public_keys = []
    for key in mock["keys"]:
        public_keys.append(bytes.fromhex(key))

    # calculate commitment
    commitment = get_ring_commitment(public_keys)

    # verify commitment
    assert commitment == bytes.fromhex(mock["expected_commitment"])


def test_valid_ring_sig():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["safrole_ticket"]

    # construct ring verifier
    verifier = RingVerifier(bytes.fromhex(mock["root"]), mock["ring_size"])

    # generate signatures
    signatures = [
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["valid_signature"]),
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["valid_signature"]),
        ),
    ]

    # verify signatures
    verifier.verify(signatures)


def test_invalid_ring_sig():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["safrole_ticket"]

    # construct ring verifier
    verifier = RingVerifier(bytes.fromhex(mock["root"]), mock["ring_size"])

    # generate signatures
    signatures = [
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["valid_signature"]),
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["invalid_signature"]),
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["invalid_signature"]),
        ),
    ]

    # verify signatures
    # signature verification should raise a ValueError
    with pytest.raises(ValueError) as e:
        verifier.verify(signatures)
    # verify the ValueError contains a dict identifying each of the invalid signatures
    assert str(e.value.args[0][1]) == str(ValueError("VRF verification failed"))
    assert str(e.value.args[0][2]) == str(ValueError("VRF verification failed"))
