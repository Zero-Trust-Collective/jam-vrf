# jam-vrf

Lightweight python bindings over the [ark-vrf](https://crates.io/crates/ark-vrf) crate for verifying JAM vrf signatures.

## Examples

### Verifying an ietf signature

```
from jam_vrf import ietf_verify

public_key = bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623")
data = bytes.fromhex("42616e646572736e6174636820766563746f72")
ad = bytes.fromhex("1f42")
signature = bytes.fromhex("6d1dd583bea262323c7dc9e94e57a472e09874e435719010eeafae503c433f166dbeeab9648505fa6a95de52d611acfbb2febacc58cdc7d0ca45abd8c952ef12ce7f4a2354a6c3f97aee6cc60c6aa4c4430b12ed0f0ef304b326c776618d7609")

try:
    ietf_verify(public_key, data, ad, signature)
except ValueError as e:
    print("invalid signature!")
```

### Generating a ring commitment

```
from jam_vrf get_ring_commitment

public_keys = [
    bytes.fromhex("7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313"),
    bytes.fromhex("d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471"),
    bytes.fromhex("561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5"),
    bytes.fromhex("b0e1f208f9d6e5b310b92014ea7ef3011e649dab038804759f3766e01029d623"),
    bytes.fromhex("4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c"),
    bytes.fromhex("86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437"),
    bytes.fromhex("ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b"),
    bytes.fromhex("3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9")
]

commitment = get_ring_commitment(public_keys)
```

### Verifying a ring signature

```
from jam_vrf RingVerifier

# safrole ticket
attempt = 1
signature = bytes.fromhex("1dfb7b61deee0c4a6899c1123e9e362f2b965079be576aebda0b7ac5e111186ec11372ea37a823a74a10a7d0c3b9b850d07ea9367f7560d0271a34125983fb0a4acb929b0817c4e3710915ea07e64d72198cbb2399e318940569d4c80ead4b5b39fa798e7a8327dcba940ffa77659b1850f877be7a439fc3a66191299d5ae92492d1a27a97455ca697913b3d7c7a9f95bfe58bda53a2641e4a0752f4efbb1a0417d77dedf11d514684f94b0729672a5808088b5445ceb540db00aa8934faa314a445e67a96d618c4fc1c100a69fa449cca1db6a7ac609d7bd04107f685411aa1bebecdb3897ed0d6c00b46a56381e5968b7520b215677afa1394464057709837dfb22b04b53c69011da7926c341cf6e77a2ed27912c40267c826cca53f876dad8a11740bbf7fec24eacf37246038a6da9d4fa923e40efb6d0a136ff2349fc1c6a1f0d199e87022d71cb503b9ea45a774988b0a3abe6f2a8bbeade7e72f14a27fd1fd2c34bf751a4397df18d16cea6ae40282ce51c36d85f5a90896070bcca248ecce27455c091c0f2e455ea83aaeac9b3c2df6cac95f34f7bd086746a414a3414f48f24f725ea802bc92a56a089f5af93122f85f7474380f3a3534553663ff34ea66f50ce876aa4bcec33ca5e7d0b16677c190d5c8365b3d55c3873b634ca53e988ca8860b97577f3b0265584b0544dde70556b35b86118c7b7c94232fb8fc30b6f407647ce39e40d0769e8a5d906f17a2ead9ab49ba3b3e669b3d48017ebf340e00a03ad82ad420ac3bc63b5f06cb15a0a938848a382ddaebabfe7b3ec13270f6c3e4c14aca85963f879bfc5937244bad613b0ed92f86205874a639fe758f3ab5c69222ea2460792c9c42732c74716886b2e8f9a155e5d439246bff0b21baf74f8e7b672c61f1328939f03be4e5d4dffa6f2d8231734a0ed8e82fef9dd00cb1ab1dfe37f0ddb12e1861570b6e4cab1ab80e774048227493bb8bad60df218b2a08e6d2230f1d040ce47e2d473d0e925b2a91abcb7f867ee2f41ad64409aa81a0937f130ebdf53e6ee61480c73708af790d1134b7a0b472573e1008b9c9d0ee95d40a3909d94e6cf0044d916ff9461844")
ring_root = bytes.fromhex("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
entropy = bytes.fromhex("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa")
ring_size = 6

# construct ring verifier
verifier = RingVRFVerifier(ring_root, ring_size)

# verify signature
try:
    verifier.verify(
        b"jam_ticket_seal" + entropy + bytes([attempt]),
        b"",
        signature
    )
except ValueError as e:
    print("invalid signature!")
```
