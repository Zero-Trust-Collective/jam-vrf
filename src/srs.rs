use ark_vrf::{
    reexports::ark_serialize::CanonicalDeserialize, ring,
    suites::bandersnatch::BandersnatchSha512Ell2,
};
use std::sync::OnceLock;

static SRS_PARAMS: OnceLock<ring::PcsParams<BandersnatchSha512Ell2>> = OnceLock::new();

// Embed the parameters file directly into the binary
const SRS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/parameters/zcash-srs-2-11-uncompressed.bin"
));

pub fn get_pcs_params() -> ring::PcsParams<BandersnatchSha512Ell2> {
    SRS_PARAMS
        .get_or_init(|| {
            ring::PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed(&SRS_BYTES[..])
                .expect("Failed to deserialize embedded SRS parameters")
        })
        .clone()
}
