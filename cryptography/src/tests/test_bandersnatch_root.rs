use crate::RingVRF;
use pyo3::Python;
use pyo3::types::PyBytes;
use pyo3::FromPyObject;

#[ignore]
#[test]
fn test_ring_vrf_bandersnatch_root_known_values() {
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
    let expected_ring = hex::decode("95f318fbd93287e8c3987874cded9b29adae70cf109c4321636fd9faeea003f8140710df8894ffbd6c84eaef4ff7cb58b17892749bb3cb3efe528eef951c688f7e83d3ede96f432de64f0b07e5c3cf0232f79ea4c221b7407f9a2348c0a0110692e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();

    // Generate root using our implementation
    Python::with_gil(|py| {
        let ring_vrf = RingVRF::new(public_keys).unwrap();
        let root = ring_vrf.root(py).unwrap();
        let root_bytes: Vec<u8> = root.extract(py).unwrap();
        assert_eq!(root_bytes.as_slice(), expected_ring.as_slice());
    });
}
