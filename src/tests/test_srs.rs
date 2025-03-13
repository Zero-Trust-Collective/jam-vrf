use crate::srs::*;
use ark_ec_vrfs::{ring, suites::bandersnatch::edwards::BandersnatchSha512Ell2};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[test]
fn test_get_pcs_params() {
    // Test that we can get the parameters without panicking
    let params = get_pcs_params();

    // Test that we can create a ring context with the parameters
    let ring_size = 6;
    let _: ring::RingContext<BandersnatchSha512Ell2> =
        ring::RingContext::from_srs(ring_size, params)
            .expect("Failed to create ring context from parameters");
}

#[test]
fn test_pcs_params_serialization_flags() {
    let params = get_pcs_params();

    // Test uncompressed serialization first since we're working with uncompressed data
    let mut uncompressed = Vec::new();
    ring::PcsParams::<BandersnatchSha512Ell2>::serialize_uncompressed(&params, &mut uncompressed)
        .expect("Failed to serialize parameters without compression");

    // Test compressed serialization
    let mut compressed = Vec::new();
    ring::PcsParams::<BandersnatchSha512Ell2>::serialize_compressed(&params, &mut compressed)
        .expect("Failed to serialize parameters with compression");

    // Verify we can deserialize both formats
    let _: ring::PcsParams<BandersnatchSha512Ell2> =
        ring::PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &uncompressed[..])
            .expect("Failed to deserialize uncompressed parameters");

    let _: ring::PcsParams<BandersnatchSha512Ell2> =
        ring::PcsParams::<BandersnatchSha512Ell2>::deserialize_compressed(&mut &compressed[..])
            .expect("Failed to deserialize compressed parameters");
}
