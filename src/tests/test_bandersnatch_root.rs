use crate::*;
use pyo3::Python;

#[test]
fn test_ring_vrf_bandersnatch_root_epoch_change() {
    // Known public keys as bytes
    let public_keys = vec![
        hex::decode("aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc").unwrap(),
        hex::decode("f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d").unwrap(),
        hex::decode("5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d").unwrap(),
        hex::decode("48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3").unwrap(),
        hex::decode("3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0").unwrap(),
        hex::decode("7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33").unwrap(),
    ];

    // Expected output ring
    let expected_ring = hex::decode("b3750bba87e39fb38579c880ff3b5c4e0aa90df8ff8be1ddc5fdd615c6780955f8fd85d99fd92a3f1d4585eb7ae8d627b01dd76d41720d73c9361a1dd2e830871155834c55db72de38fb875a9470faedb8cae54b34f7bfe196a9caca00c2911592e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();

    // Generate root using our implementation
    Python::with_gil(|py| {
        let commitment = get_ring_commitment(py, public_keys).unwrap();
        assert_eq!(commitment.as_bytes(py), expected_ring.as_slice());
    });
}

#[test]
fn test_ring_vrf_bandersnatch_root_no_epoch_change() {
    // Known public keys as bytes
    let public_keys = vec![
        hex::decode("5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d").unwrap(),
        hex::decode("3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0").unwrap(),
        hex::decode("aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc").unwrap(),
        hex::decode("7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33").unwrap(),
        hex::decode("48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3").unwrap(),
        hex::decode("f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d").unwrap(),
    ];

    // Expected output ring
    let expected_ring = hex::decode("a949a60ad754d683d398a0fb674a9bbe525ca26b0b0b9c8d79f210291b40d286d9886a9747a4587d497f2700baee229ca72c54ad652e03e74f35f075d0189a40d41e5ee65703beb5d7ae8394da07aecf9056b98c61156714fd1d9982367bee2992e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();

    // Generate root using our implementation
    Python::with_gil(|py| {
        let commitment = get_ring_commitment(py, public_keys).unwrap();
        assert_eq!(commitment.as_bytes(py), expected_ring.as_slice());
    });
}
