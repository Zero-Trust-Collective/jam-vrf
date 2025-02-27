use std::sync::OnceLock;
use ark_serialize::CanonicalDeserialize;
use ark_ec_vrfs::{
    ring,
    suites::bandersnatch::edwards::BandersnatchSha512Ell2,
};

static SRS_PARAMS: OnceLock<ring::PcsParams<BandersnatchSha512Ell2>> = OnceLock::new();

// Embed the parameters file directly into the binary
const SRS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/parameters/zcash-srs-2-11-uncompressed.bin"
));

pub fn get_pcs_params() -> ring::PcsParams<BandersnatchSha512Ell2> {
    SRS_PARAMS.get_or_init(|| {
        ring::PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed(&mut &SRS_BYTES[..])
            .expect("Failed to deserialize embedded SRS parameters")
    }).clone()
}
