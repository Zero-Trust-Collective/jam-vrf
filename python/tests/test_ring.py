from jam_vrf import RingVerifier, get_ring_commitment
import pytest
import json

def test_ring_commitment():
    # test vector sourced from: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ring.json#L123
    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["valid_commitment"]

    # compose list of public key bytes
    public_keys = []
    for key in mock["keys"]:
        public_keys.append(bytes.fromhex(key))

    # calculate commitment
    commitment = get_ring_commitment(public_keys)

    # verify commitment
    assert commitment == bytes.fromhex(mock["commitment"])


def test_valid_ring_sig():
    """
    Verify ring VRF signature of a valid jam ticket.
    
    testvector sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
    """

    # load mock data
    with open("mocks.json", "r") as f:
        mock = json.load(f)["ring"]["valid_signature"]

    # construct ring verifier
    verifier = RingVerifier(bytes.fromhex(mock["root"]), mock["ring_size"])

    # generate signatures
    signatures = [
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["signature"])
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(mock["entropy"]) + bytes([mock["attempt"]]),
            b"",
            bytes.fromhex(mock["signature"])
        ),
    ]

    # verify signatures
    verifier.verify(signatures)

def test_invalid_ring_sig():
    """
    Verify ring VRF signature of an invalid jam ticket.
    
    valid mock signature data sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
    invalid mock signature data sourced from: https://github.com/davxy/jam-test-vectors/blob/25aaedc8abc8c617287d9df56c916794db82eb92/safrole/tiny/publish-tickets-no-mark-3.json#L8
    """

    # load mock data
    with open("mocks.json", "r") as f:
        json_data = json.load(f)
        valid_mock = json_data["ring"]["valid_signature"]
        invalid_mock = json_data["ring"]["invalid_signature"]

    # construct ring verifier
    verifier = RingVerifier(bytes.fromhex(valid_mock["root"]), valid_mock["ring_size"])

    # generate signatures
    signatures = [
        (
            b"jam_ticket_seal" + bytes.fromhex(valid_mock["entropy"]) + bytes([valid_mock["attempt"]]),
            b"",
            bytes.fromhex(valid_mock["signature"])
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(invalid_mock["entropy"]) + bytes([invalid_mock["attempt"]]),
            b"",
            bytes.fromhex(invalid_mock["signature"])
        ),
        (
            b"jam_ticket_seal" + bytes.fromhex(invalid_mock["entropy"]) + bytes([invalid_mock["attempt"]]),
            b"",
            bytes.fromhex(invalid_mock["signature"])
        ),
    ]

    # verify signatures
    # signature verification should raise a ValueError
    with pytest.raises(ValueError) as e:
        verifier.verify(signatures)
    # verify the ValueError contains a dict identifying each of the invalid signatures
    assert str(e.value.args[0][1]) == str(ValueError('VRF verification failed'))
    assert str(e.value.args[0][2]) == str(ValueError('VRF verification failed'))
