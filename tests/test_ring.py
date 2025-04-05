from jam_vrf import RingVerifier, get_ring_commitment
import pytest

def test_ring_commitment():
    # test vector sourced from: https://github.com/davxy/bandersnatch-vrf-spec/blob/6b1ceba5b3cbc834201732bcdad1377e19e9283e/assets/vectors/bandersnatch_sha-512_ell2_ring.json#L123
    # public keys
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

    # verify commitment
    expected_commitment = bytes.fromhex("a359e70e307799b111ad89b162b4260fb4a96ebf4232e8b02d396033498d4216305ed9cff3584a4c68f03ab3df87243a80bfc965633efc23c82ca064afe105baacccbf23e47b543d16c3c4466a83242a77acc16f79b8710051b5e97c85319cf392e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
    assert commitment == expected_commitment


def test_valid_ring_sig():
    """
    Verify ring VRF signature of a valid jam ticket.
    
    testvector sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
    """

    # safrole ticket
    attempt = 1
    signature = bytes.fromhex("1dfb7b61deee0c4a6899c1123e9e362f2b965079be576aebda0b7ac5e111186ec11372ea37a823a74a10a7d0c3b9b850d07ea9367f7560d0271a34125983fb0a4acb929b0817c4e3710915ea07e64d72198cbb2399e318940569d4c80ead4b5b39fa798e7a8327dcba940ffa77659b1850f877be7a439fc3a66191299d5ae92492d1a27a97455ca697913b3d7c7a9f95bfe58bda53a2641e4a0752f4efbb1a0417d77dedf11d514684f94b0729672a5808088b5445ceb540db00aa8934faa314a445e67a96d618c4fc1c100a69fa449cca1db6a7ac609d7bd04107f685411aa1bebecdb3897ed0d6c00b46a56381e5968b7520b215677afa1394464057709837dfb22b04b53c69011da7926c341cf6e77a2ed27912c40267c826cca53f876dad8a11740bbf7fec24eacf37246038a6da9d4fa923e40efb6d0a136ff2349fc1c6a1f0d199e87022d71cb503b9ea45a774988b0a3abe6f2a8bbeade7e72f14a27fd1fd2c34bf751a4397df18d16cea6ae40282ce51c36d85f5a90896070bcca248ecce27455c091c0f2e455ea83aaeac9b3c2df6cac95f34f7bd086746a414a3414f48f24f725ea802bc92a56a089f5af93122f85f7474380f3a3534553663ff34ea66f50ce876aa4bcec33ca5e7d0b16677c190d5c8365b3d55c3873b634ca53e988ca8860b97577f3b0265584b0544dde70556b35b86118c7b7c94232fb8fc30b6f407647ce39e40d0769e8a5d906f17a2ead9ab49ba3b3e669b3d48017ebf340e00a03ad82ad420ac3bc63b5f06cb15a0a938848a382ddaebabfe7b3ec13270f6c3e4c14aca85963f879bfc5937244bad613b0ed92f86205874a639fe758f3ab5c69222ea2460792c9c42732c74716886b2e8f9a155e5d439246bff0b21baf74f8e7b672c61f1328939f03be4e5d4dffa6f2d8231734a0ed8e82fef9dd00cb1ab1dfe37f0ddb12e1861570b6e4cab1ab80e774048227493bb8bad60df218b2a08e6d2230f1d040ce47e2d473d0e925b2a91abcb7f867ee2f41ad64409aa81a0937f130ebdf53e6ee61480c73708af790d1134b7a0b472573e1008b9c9d0ee95d40a3909d94e6cf0044d916ff9461844")
    ring_root = bytes.fromhex("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
    entropy = bytes.fromhex("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa")
    ring_size = 6

    # construct ring verifier
    verifier = RingVerifier(ring_root, ring_size)

    # verify signature
    verifier.verify(
        b"jam_ticket_seal" + entropy + bytes([attempt]),
        b"",
        signature
    )

def test_invalid_ring_sig():
    """
    Verify ring VRF signature of an invalid jam ticket.
    
    testvector sourced from: https://github.com/davxy/jam-test-vectors/blob/polkajam-vectors/safrole/tiny/publish-tickets-no-mark-6.json
    """

    # safrole ticket
    attempt = 1
    signature = bytes.fromhex("1dfb7b61deee0c4a6899c1123e9e362f2b965079be576aebda0b7ac5e111186e45649b3aa58e18cb4faa3cc74688a322fcd5ab4d591dc2e183f4e31f3f5b926fefcb067f0b43fc9bda32af4bdcbf8767945d01e9816327857a3537929a304eea39fa798e7a8327dcba940ffa77659b1850f877be7a439fc3a66191299d5ae9240e005d84cfbd9fe9a1b250873d484fdf90a03e6b3238a3143f3692ef3128cf1961c8246ca93c957ea7907f7d1dd80e745ecada3f48dbdcbf14dca402df264303a445e67a96d618c4fc1c100a69fa449cca1db6a7ac609d7bd04107f685411aa1bebecdb3897ed0d6c00b46a56381e5968b7520b215677afa1394464057709837dfb22b04b53c69011da7926c341cf6e77a2ed27912c40267c826cca53f876dad8952d2acaa7ebb6da732dd2e34cc2211a953d575e70137e69ce03526f0677ffc2c77f3488b19a3383188e0beaa03fd32b97e7a991fadd8d9d2c71a2d37c836adba04e6f9b5a9f58ecdfb3aaaada4161e283ecb8c295efdf53635ba73ca20f47181e9d7529da701fb654d55d99ff7a9af4c5b678f7ba7d764c48ea2b15569ee1d20a10029a50d5b1100356b64916c6c38526d1dac1f169e5f4250f27dd9cb7454af6591aac3e7353b3a083f310d735eb7a7530fcddc3d06fad7efbca9bf7e3e22306fa2dfd6a184cf5d0acc29ef7cc35c07a7c1e2fc75bb42c80834f000c5d85b293f40ed6b605ec94df44d87712eec2ad1d1386564e5fd2491ec42317aea9058a44e850b08e2a2c4d261c7c59a96be65d89555285c24326c052b5d102cb8a8341b97fcdb28bf8ad1a5591613dc119f7bc44abba455075baf954149a05ae35f13a1e585445577cd9f13c20a04194307716df5f290403147dc728cff8324ee06b0724bbd11fb59a4f3d717a15726c41113e1fd7adcacb5e303a974dd1f6b74028bd1c61f204a43a8ec0bdcf161ff8f2310ac411ceb866d641d29ca3e68fa259f6ee960d3d5835f930f788a3021c5467b619dbc9e5b8b80a6bdac820d1f56fa282fac56c299a7b2cd1d7b2d9b81e6c28bf2a7d6da6b40a02f4ba2aee0f37311c16b941aeaa11e6e40b16f91cad2089ccfc3")
    ring_root = bytes.fromhex("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf")
    entropy = bytes.fromhex("bb30a42c1e62f0afda5f0a4e8a562f7a13a24cea00ee81917b86b89e801314aa")
    ring_size = 6

    # construct ring verifier
    verifier = RingVerifier(ring_root, ring_size)

    # verify signature
    with pytest.raises(ValueError, match="VRF verification failed"):
        verifier.verify(
            b"jam_ticket_seal" + entropy + bytes([attempt]),
            b"",
            signature
        )
