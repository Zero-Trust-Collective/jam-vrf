use crate::*;

#[test]
fn test_single_signature_vrf() {
    // Initialize Python
    pyo3::prepare_freethreaded_python();

    // Generate key pair
    let key_pair = KeyPairVRF::new();
    let data = b"test data";
    let ad = b"additional data";

    // Generate proof and output
    let proof_and_output = SingleVRF::prove(&key_pair, data, ad).unwrap();

    // Verify proof
    Python::with_gil(|py| {
        let pk_bytes = key_pair.public_key_bytes(py).unwrap();
        let result = SingleVRF::verify(pk_bytes.as_bytes(), data, ad, &proof_and_output).unwrap();
        assert!(result);
    });
}

#[test]
fn test_ring_signature_vrf() {
    // Initialize Python
    pyo3::prepare_freethreaded_python();

    // Generate multiple key pairs for the ring
    let key_pair1 = KeyPairVRF::new();
    let key_pair2 = KeyPairVRF::new();
    let key_pair3 = KeyPairVRF::new();

    Python::with_gil(|py| {
        let pk1_bytes = key_pair1.public_key_bytes(py).unwrap();
        let pk2_bytes = key_pair2.public_key_bytes(py).unwrap();
        let pk3_bytes = key_pair3.public_key_bytes(py).unwrap();

        let ring_public_keys = vec![
            pk1_bytes.as_bytes(),
            pk2_bytes.as_bytes(),
            pk3_bytes.as_bytes(),
        ];

        let data = b"test data";
        let ad = b"additional data";

        // Generate proof and output using first key pair
        let proof_and_output = RingVRF::prove(&key_pair1, ring_public_keys.clone(), 0, data, ad).unwrap();

        // Verify proof
        let result = RingVRF::verify(ring_public_keys.clone(), data, ad, &proof_and_output).unwrap();
        assert!(result);

        // Test bandersnatch root generation
        let root = RingVRF::bandersnatch_root(ring_public_keys).unwrap();
        assert!(!root.as_ref(py).as_bytes().is_empty());
    });
}
