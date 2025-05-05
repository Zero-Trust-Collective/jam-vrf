from jam_vrf import RingVerifier, get_ring_commitment
import pytest
import json


def test_commitment_generation():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["commitment"]

    # compose list of public key bytes
    public_keys = []
    for key in mock["keys"]:
        public_keys.append(bytes.fromhex(key))

    # generate commitment
    commitment = get_ring_commitment(public_keys)

    # verify commitment
    assert commitment == bytes.fromhex(mock["expected_commitment"])


def test_signature_verification():
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["safrole_ticket"]

    # construct ring verifier
    verifier = RingVerifier(bytes.fromhex(mock["root"]), mock["ring_size"])

    # generate batch of valid signatures
    signatures = []
    for _ in range(2):
        signatures.append(
            (
                b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
                b"",
                bytes.fromhex(mock["signature"]),
            )
        )

    # verify valid signatures
    verifier.verify(signatures)

    # verify batch that contains invalid signatures
    signatures.append(
        (
            b"wrong_data",  # data is different from what was signed
            b"",
            bytes.fromhex(mock["signature"]),
        )
    )
    signatures.append(
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"wrong_ad",  # ad is different from what was signed
            bytes.fromhex(mock["signature"]),
        )
    )
    # signature verification should raise a ValueError
    with pytest.raises(ValueError) as e:
        verifier.verify(signatures)
    # verify the ValueError contains a dict identifying each of the invalid signatures
    assert len(e.value.args[0]) == 2
    assert str(e.value.args[0][2]) == str(ValueError("VRF verification failed"))
    assert str(e.value.args[0][3]) == str(ValueError("VRF verification failed"))
