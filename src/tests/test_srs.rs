use crate::srs::*;
use ark_vrf::suites::bandersnatch::RingProofParams;

#[test]
fn test_get_pcs_params() {
    // Test that we can get the parameters without panicking
    let pc_params = get_pcs_params();

    // Test that we can create a ring context with the parameters
    let ring_size = 6;
    let _ = RingProofParams::from_pcs_params(ring_size, pc_params)
        .expect("Failed to initialize ring proof params from pcs params");
}
