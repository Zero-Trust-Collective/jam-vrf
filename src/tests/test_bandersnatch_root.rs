use crate::*;
use pyo3::Python;

#[test]
fn test_ring_commitment() {
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
    let expected_ring = hex::decode("85f9095f4abd040839d793d89ab5ff25c61e50c844ab6765e2c0b22373b5a8f6fbe5fc0cd61fdde580b3d44fe1be127197e33b91960b10d2c6fc75aec03f36e16c2a8204961097dbc2c5ba7655543385399cc9ef08bf2e520ccf3b0a7569d88492e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf").unwrap();

    // Generate root using our implementation
    Python::with_gil(|py| {
        let commitment = get_ring_commitment(py, public_keys).unwrap();
        assert_eq!(commitment.as_bytes(py), expected_ring.as_slice());
    });
}
