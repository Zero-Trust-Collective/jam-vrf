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
    let (proof, output) = SingleVRF::prove(&key_pair, data, ad).unwrap();

    Python::with_gil(|py| {
        let pk_bytes = key_pair.public_key_bytes(py).unwrap();
        
        // Test serialization/deserialization of proof
        let proof_bytes = proof.bytes(py).unwrap();
        let reconstructed_proof = SingleVRFProof::new(proof_bytes.as_bytes(py)).unwrap();
        
        // Test serialization/deserialization of output
        let output_bytes = output.bytes(py).unwrap();
        let reconstructed_output = VRFOutput::new(output_bytes.as_bytes(py)).unwrap();
        
        // Verify reconstructed proof and output
        let result = SingleVRF::verify(
            pk_bytes.as_bytes(py), 
            data, 
            ad, 
            &reconstructed_proof, 
            &reconstructed_output
        ).unwrap();
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

        let ring_public_keys: Vec<Vec<u8>> = vec![
            pk1_bytes.as_bytes(py).to_vec(),
            pk2_bytes.as_bytes(py).to_vec(),
            pk3_bytes.as_bytes(py).to_vec(),
        ];

        let data = b"test data";
        let ad = b"additional data";

        // Create RingVRF instance with the ring public keys
        let ring_vrf = RingVRF::new(ring_public_keys.clone()).unwrap();

        // Generate proof and output using first key pair
        let (proof, output) = ring_vrf.prove(&key_pair1, 0, data, ad).unwrap();

        // Test serialization/deserialization of proof
        let proof_bytes = proof.bytes(py).unwrap();
        let reconstructed_proof = RingVRFProof::new(proof_bytes.as_bytes(py)).unwrap();
        
        // Test serialization/deserialization of output
        let output_bytes = output.bytes(py).unwrap();
        let reconstructed_output = VRFOutput::new(output_bytes.as_bytes(py)).unwrap();

        // Verify reconstructed proof and output
        let result = ring_vrf.verify(data, ad, &reconstructed_proof, &reconstructed_output).unwrap();
        assert!(result);

        // Test root generation
        let root = ring_vrf.root(py).unwrap();
        assert!(!root.as_bytes(py).is_empty());
    });
}

#[test]
fn test_invalid_proof_bytes() {
    pyo3::prepare_freethreaded_python();
    
    Python::with_gil(|_py| {
        // Test with empty bytes
        assert!(SingleVRFProof::new(&[]).is_err());
        assert!(RingVRFProof::new(&[]).is_err());
        
        // Test with invalid bytes
        let invalid_bytes = vec![1, 2, 3, 4];
        assert!(SingleVRFProof::new(&invalid_bytes).is_err());
        assert!(RingVRFProof::new(&invalid_bytes).is_err());
    });
}
